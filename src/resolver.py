"""A minimal iterative DNS resolver with on-disk caching.

Instead of relying on a single (possibly rate-limited) recursive resolver,
this module performs the iterative resolution itself: starting at the root
servers, it follows referrals (NS records + glue) down to the authoritative
servers for a given name, exactly like a real recursive resolver would do
internally. Every answer (and every intermediate NS/glue lookup) is cached
both in memory and on disk (keyed by name+type) so that a domain occurring
in several blocklists -- or resolved again on a later run before its TTL
expires -- is never queried twice.
"""

from __future__ import annotations

import json
import random
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.rdtypes.ANY.NS
import dns.resolver

# IPv4 addresses of the 13 root name servers (IANA root hints, 2024).
ROOT_SERVERS: List[str] = [
    "198.41.0.4",     # a.root-servers.net
    "199.9.14.201",   # b.root-servers.net
    "192.33.4.12",    # c.root-servers.net
    "199.7.91.13",    # d.root-servers.net
    "192.203.230.10", # e.root-servers.net
    "192.5.5.241",    # f.root-servers.net
    "192.112.36.4",   # g.root-servers.net
    "198.97.190.53",  # h.root-servers.net
    "192.36.148.17",  # i.root-servers.net
    "192.58.128.30",  # j.root-servers.net
    "193.0.14.129",   # k.root-servers.net
    "199.7.83.42",    # l.root-servers.net
    "202.12.27.33",   # m.root-servers.net
]

MAX_REFERRALS = 20
QUERY_TIMEOUT = 3.0
QUERY_RETRIES = 2


class DiskCache:
    """A very small JSON-backed cache, keyed by "name|rdtype"."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self._data: Dict[str, Any] = {}
        if self.path.exists():
            try:
                self._data = json.loads(self.path.read_text())
            except (json.JSONDecodeError, OSError):
                self._data = {}

    @staticmethod
    def _key(name: str, rdtype: str) -> str:
        return f"{name.lower().rstrip('.')}|{rdtype.upper()}"

    def get(self, name: str, rdtype: str) -> Optional[Any]:
        entry = self._data.get(self._key(name, rdtype))
        if entry is None:
            return None
        if entry.get("expires", 0) < time.time():
            return None
        return entry["value"]

    def set(self, name: str, rdtype: str, value: Any, ttl: int = 3600) -> None:
        with self._lock:
            self._data[self._key(name, rdtype)] = {
                "value": value,
                "expires": time.time() + max(ttl, 60),
            }

    def save(self) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self._data))


class IterativeResolver:
    """Performs manual iterative DNS resolution, with caching.

    This deliberately avoids sending every query to a single public
    resolver: it walks the DNS delegation chain itself (root -> TLD ->
    ... -> authoritative), which spreads queries across many different
    name servers and lets us cache aggressively at every level.
    """

    def __init__(self, cache_path: Optional[Path] = None):
        self.cache = DiskCache(cache_path or Path(".dns_cache.json"))
        # In-memory memoisation for the current process, on top of the
        # disk cache, to avoid re-parsing JSON for repeated lookups.
        self._mem: Dict[str, Any] = {}

    # -- low level -----------------------------------------------------
    def _send_query(self, server_ip: str, qname: str, rdtype: str) -> Optional[dns.message.Message]:
        q = dns.message.make_query(qname, rdtype, want_dnssec=False)
        for attempt in range(QUERY_RETRIES):
            try:
                response = dns.query.udp(q, server_ip, timeout=QUERY_TIMEOUT)
                if response.flags & dns.flags.TC:
                    response = dns.query.tcp(q, server_ip, timeout=QUERY_TIMEOUT)
                return response
            except (dns.exception.Timeout, OSError, dns.exception.DNSException):
                continue
        return None

    # -- iterative resolution -------------------------------------------
    def _resolve_iterative(self, qname: str, rdtype: str) -> Tuple[List[str], List[Dict[str, str]]]:
        """Resolve `qname`/`rdtype` starting from the root, following
        referrals. Returns (answer_values, authoritative_nameservers)."""

        servers = list(ROOT_SERVERS)
        random.shuffle(servers)
        seen_zones = set()
        last_ns_names: List[str] = []

        for _ in range(MAX_REFERRALS):
            response = None
            for ip in servers:
                response = self._send_query(ip, qname, rdtype)
                if response is not None:
                    break
            if response is None:
                return [], []

            # Direct answer.
            if response.answer:
                values: List[str] = []
                cname_target = None
                for rrset in response.answer:
                    for rdata in rrset:
                        if rdata.rdtype == dns.rdatatype.CNAME:
                            cname_target = rdata.target.to_text()
                        elif dns.rdatatype.to_text(rdata.rdtype) == rdtype:
                            values.append(rdata.to_text())
                if values:
                    return values, self._ns_info(last_ns_names, servers)
                if cname_target:
                    # Follow CNAME chain (fresh iterative lookup, cached).
                    values = self.resolve(cname_target, rdtype)
                    return values, self._ns_info(last_ns_names, servers)
                return [], self._ns_info(last_ns_names, servers)

            # No direct answer: look for a referral (NS records) in authority.
            ns_names = []
            zone = None
            for rrset in response.authority:
                if rrset.rdtype == dns.rdatatype.NS:
                    zone = rrset.name.to_text()
                    for rdata in rrset:
                        ns_names.append(rdata.target.to_text())

            if not ns_names:
                # No delegation and no answer -> NXDOMAIN / NODATA.
                return [], self._ns_info(last_ns_names, servers)

            if zone in seen_zones:
                # Avoid infinite referral loops.
                return [], self._ns_info(ns_names, servers)
            seen_zones.add(zone)
            last_ns_names = ns_names

            # Try glue records first (additional section).
            glue_ips = []
            for rrset in response.additional:
                if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                    for rdata in rrset:
                        glue_ips.append(rdata.to_text())

            if glue_ips:
                servers = glue_ips
                continue

            # No glue: resolve NS hostnames ourselves (cached).
            resolved_ips = []
            for ns_name in ns_names[:4]:  # cap to limit query fan-out
                ips = self.resolve(ns_name, "A")
                resolved_ips.extend(ips)
            if not resolved_ips:
                return [], self._ns_info(ns_names, servers)
            servers = resolved_ips

        return [], []

    def _ns_info(self, ns_names: List[str], server_ips: List[str]) -> List[Dict[str, str]]:
        info = []
        for name in ns_names:
            ips = self.resolve(name, "A")
            for ip in ips:
                info.append({"name": name, "ip": ip})
            if not ips:
                info.append({"name": name, "ip": None})
        return info

    # -- public, cached entry point --------------------------------------
    def resolve(self, qname: str, rdtype: str) -> List[str]:
        qname = qname.rstrip(".") + "."
        cached = self.cache.get(qname, rdtype)
        if cached is not None:
            return cached
        mem_key = f"{qname}|{rdtype}"
        if mem_key in self._mem:
            return self._mem[mem_key]

        try:
            values, _ = self._resolve_iterative(qname, rdtype)
        except RecursionError:
            values = []

        self.cache.set(qname, rdtype, values)
        self._mem[mem_key] = values
        return values

    def resolve_full(self, domain: str) -> Dict[str, Any]:
        """Resolve A, AAAA and authoritative NS (+ their IPs) for domain."""
        domain = domain.rstrip(".") + "."
        cache_key = f"full|{domain}"
        if cache_key in self._mem:
            return self._mem[cache_key]
        cached = self.cache.get(domain, "FULL")
        if cached is not None:
            self._mem[cache_key] = cached
            return cached

        a_records = self.resolve(domain, "A")
        aaaa_records = self.resolve(domain, "AAAA")
        ns_values, ns_info = self._resolve_iterative(domain, "NS")

        result = {
            "domain": domain.rstrip("."),
            "a": sorted(set(a_records)),
            "aaaa": sorted(set(aaaa_records)),
            "nameservers": ns_values or [n["name"] for n in ns_info],
            "nameserver_ips": [n for n in ns_info if n.get("ip")],
        }
        self.cache.set(domain, "FULL", result)
        self._mem[cache_key] = result
        return result

    def save(self) -> None:
        self.cache.save()


# dns.flags is needed above; imported lazily to keep top import block tidy.
import dns.flags  # noqa: E402

