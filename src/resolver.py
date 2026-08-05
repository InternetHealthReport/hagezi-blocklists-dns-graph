"""A minimal iterative DNS resolver with an in-memory cache.

Instead of relying on a single (possibly rate-limited) recursive resolver,
this module performs the iterative resolution itself: starting at the root
servers, it follows referrals (NS records + glue) down to the authoritative
servers for a given name, exactly like a real recursive resolver would do
internally. Every answer (and every intermediate NS/glue lookup) is cached
in memory (keyed by name+type) so that a domain occurring in several
blocklists is never queried twice during a run.
"""

from __future__ import annotations

import random
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

import dns.exception
import dns.flags
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

# Default TTL for positive answers held in the in-memory cache.
POSITIVE_CACHE_TTL = 3600

# TTL used for caching *negative* results (NXDOMAIN / NODATA / a lookup
# that failed entirely). Kept much shorter than the default positive-answer
# TTL so that a domain that is currently dead but gets re-registered (or a
# transient resolution failure) doesn't stay "stuck" as unresolvable for too
# long, while still avoiding hammering the same dead domain over and over
# within a single scan.
NEGATIVE_CACHE_TTL = 300

# Cap on how many nameserver hostnames we resolve ourselves when a referral
# comes back without glue records, to limit query fan-out.
MAX_GLUELESS_NS = 4


class MemoryCache:
    """A small thread-safe in-memory cache, keyed by "name|rdtype"."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._data: Dict[str, Any] = {}

    @staticmethod
    def _key(name: str, rdtype: str) -> str:
        return f"{name.lower().rstrip('.')}|{rdtype.upper()}"

    def get(self, name: str, rdtype: str) -> Optional[Any]:
        with self._lock:
            entry = self._data.get(self._key(name, rdtype))
            if entry is None:
                return None
            if entry["expires"] < time.time():
                return None
            return entry["value"]

    def set(self, name: str, rdtype: str, value: Any, ttl: int = POSITIVE_CACHE_TTL) -> None:
        with self._lock:
            self._data[self._key(name, rdtype)] = {
                "value": value,
                "expires": time.time() + max(ttl, 60),
            }


class IterativeResolver:
    """Performs manual iterative DNS resolution, with in-memory caching.

    This deliberately avoids sending every query to a single public
    resolver: it walks the DNS delegation chain itself (root -> TLD ->
    ... -> authoritative), which spreads queries across many different
    name servers and lets us cache aggressively at every level.
    """

    def __init__(self) -> None:
        self.cache = MemoryCache()
        # Per-thread recursion guard: resolving the NS hostnames for a zone
        # sometimes requires resolving NS hostnames that are themselves
        # (glueless) subdomains of the zone being resolved, which can lead
        # to infinite recursion (e.g. ns.example.com being served by
        # ns.example.com itself, with no glue). This tracks names currently
        # "in flight" per thread so such cycles short-circuit instead of
        # hanging forever.
        self._in_progress = threading.local()

        # Zone-cut cache: maps a delegated zone name (e.g. "com.") to the
        # IPs of its authoritative servers. Since thousands of domains in a
        # blocklist typically share only a handful of TLDs (and often the
        # same second-level zone), remembering "com." -> [gtld ips] lets us
        # jump straight past the root servers for every subsequent lookup
        # instead of re-walking the referral chain from scratch each time.
        # This is the single biggest speedup for bulk resolution.
        self._zone_lock = threading.Lock()
        self._zone_cache: Dict[str, List[str]] = {}

    # -- low level -----------------------------------------------------
    def _send_query(self, server_ip: str, qname: str, rdtype: str) -> Optional[dns.message.Message]:
        q = dns.message.make_query(qname, rdtype, want_dnssec=False)
        for _attempt in range(QUERY_RETRIES):
            try:
                response = dns.query.udp(q, server_ip, timeout=QUERY_TIMEOUT)
                if response.flags & dns.flags.TC:
                    response = dns.query.tcp(q, server_ip, timeout=QUERY_TIMEOUT)
                return response
            except (dns.exception.Timeout, OSError, dns.exception.DNSException):
                continue
        return None

    def _first_response(
        self, servers: List[str], qname: str, rdtype: str
    ) -> Optional[dns.message.Message]:
        """Query `servers` in order, returning the first usable response."""
        for ip in servers:
            response = self._send_query(ip, qname, rdtype)
            if response is not None:
                return response
        return None

    # -- zone-cut cache ---------------------------------------------------
    @staticmethod
    def _suffixes(qname: str) -> List[str]:
        """Return the ancestor zone names of `qname`, longest first.

        e.g. "a.b.example.com." -> ["a.b.example.com.", "b.example.com.",
        "example.com.", "com."]. Used to probe the zone-cut cache with a
        handful of direct dict lookups instead of scanning every known zone.
        """
        try:
            name = dns.name.from_text(qname)
        except dns.exception.DNSException:
            return []
        labels = name.labels
        # Keep the trailing root label so the generated names are absolute
        # ("com." rather than "com") and match the zone-cache keys, which
        # come straight from the wire format.
        return [
            dns.name.Name(labels[i:]).to_text() for i in range(len(labels) - 1)
        ]

    def _best_cached_zone(self, qname: str) -> Optional[Tuple[str, List[str]]]:
        """Return (zone, server_ips) for the longest cached zone that is an
        ancestor of (or equal to) `qname`, if any. This lets us skip
        straight to e.g. the ".com" TLD servers -- or even a specific
        second-level zone's servers -- instead of always starting the
        referral walk from the 13 root servers.

        Rather than scanning (and re-parsing) every entry of the zone cache,
        which serialises all worker threads on a single lock and costs
        O(#zones) per lookup, this walks the query name's own suffixes from
        longest to shortest and does a plain dict lookup for each -- at most
        one lookup per label.
        """
        candidates = self._suffixes(qname)
        if not candidates:
            return None
        with self._zone_lock:
            for candidate in candidates:
                ips = self._zone_cache.get(candidate)
                if ips:
                    return candidate, list(ips)
        return None

    def _cache_zone(self, zone: str, server_ips: List[str]) -> None:
        if not zone or not server_ips:
            return
        with self._zone_lock:
            try:
                name = dns.name.from_text(zone)
            except dns.exception.DNSException:
                return
            self._zone_cache[name.to_text()] = list(server_ips)

    # -- iterative resolution -------------------------------------------
    def _extract_answer(
        self, response: dns.message.Message, rdtype: str
    ) -> Tuple[List[str], Optional[str]]:
        """Pull the values matching `rdtype` (and any CNAME target) out of a
        response's answer section."""
        values: List[str] = []
        cname_target: Optional[str] = None
        for rrset in response.answer:
            for rdata in rrset:
                if rdata.rdtype == dns.rdatatype.CNAME:
                    cname_target = rdata.target.to_text()
                elif dns.rdatatype.to_text(rdata.rdtype) == rdtype:
                    values.append(rdata.to_text())
        return values, cname_target

    def _resolve_iterative(
        self, qname: str, rdtype: str, with_ns_info: bool = False
    ) -> Tuple[List[str], List[Dict[str, str]], Optional[str], List[str]]:
        """Resolve `qname`/`rdtype`, following referrals.

        Returns (answer_values, nameserver_info, zone, final_servers).

        `zone` is the name of the deepest delegated zone encountered while
        walking the referral chain (i.e. the zone whose authoritative
        nameservers were ultimately queried) -- this is effectively the
        registered/second-level domain the queried name belongs to, as
        determined directly from the real DNS delegation chain rather than
        from a static public-suffix list.

        `final_servers` is the list of server IPs that produced the final
        response, so a caller needing several record types for the same name
        can reuse them instead of walking the delegation chain again.

        `nameserver_info` is only populated when `with_ns_info` is true:
        building it requires resolving each nameserver hostname's address,
        which is a large amount of extra fan-out that most callers discard.
        """

        # Skip straight to the deepest known zone-cut instead of always
        # starting the walk at the 13 root servers: this is what turns an
        # O(depth) referral chain per domain into essentially O(1) once the
        # TLD (and often the SLD) has already been resolved once.
        cached_zone = self._best_cached_zone(qname)
        if cached_zone is not None:
            servers = list(cached_zone[1])
        else:
            servers = list(ROOT_SERVERS)
            random.shuffle(servers)

        seen_zones = set()
        last_ns_names: List[str] = []
        last_zone: Optional[str] = None

        def ns_info(names: List[str]) -> List[Dict[str, str]]:
            return self._ns_info(names) if with_ns_info else []

        for _ in range(MAX_REFERRALS):
            response = self._first_response(servers, qname, rdtype)
            if response is None:
                return [], [], last_zone, servers

            # Direct answer.
            if response.answer:
                values, cname_target = self._extract_answer(response, rdtype)
                if not values and cname_target:
                    # Follow CNAME chain (fresh iterative lookup, cached).
                    values = self.resolve(cname_target, rdtype)
                return values, ns_info(last_ns_names), last_zone, servers

            # No direct answer: look for a referral (NS records) in authority.
            ns_names: List[str] = []
            zone = None
            for rrset in response.authority:
                if rrset.rdtype == dns.rdatatype.NS:
                    zone = rrset.name.to_text()
                    for rdata in rrset:
                        ns_names.append(rdata.target.to_text())

            if not ns_names:
                # No delegation and no answer -> NXDOMAIN / NODATA.
                return [], ns_info(last_ns_names), last_zone, servers

            if zone in seen_zones:
                # Avoid infinite referral loops.
                return [], ns_info(ns_names), last_zone, servers
            seen_zones.add(zone)
            last_ns_names = ns_names
            last_zone = zone

            # Try glue records first (additional section).
            glue_ips = []
            for rrset in response.additional:
                if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                    for rdata in rrset:
                        glue_ips.append(rdata.to_text())

            if glue_ips:
                servers = glue_ips
                # Remember this zone-cut so future lookups for the same
                # (or a sibling/descendant) name can start right here
                # instead of walking the whole chain from the root again.
                self._cache_zone(zone, servers)
                continue

            # No glue: resolve NS hostnames ourselves (cached).
            resolved_ips: List[str] = []
            for ns_name in ns_names[:MAX_GLUELESS_NS]:
                resolved_ips.extend(self.resolve(ns_name, "A"))
            if not resolved_ips:
                return [], ns_info(ns_names), last_zone, servers
            servers = resolved_ips
            self._cache_zone(zone, servers)

        return [], [], last_zone, servers

    def _ns_info(self, ns_names: List[str]) -> List[Dict[str, str]]:
        info = []
        for name in ns_names:
            ips = self.resolve(name, "A")
            if ips:
                info.extend({"name": name, "ip": ip} for ip in ips)
            else:
                info.append({"name": name, "ip": None})
        return info

    # -- public, cached entry point --------------------------------------
    def resolve(self, qname: str, rdtype: str) -> List[str]:
        qname = qname.rstrip(".") + "."
        cached = self.cache.get(qname, rdtype)
        if cached is not None:
            return cached

        in_progress = getattr(self._in_progress, "keys", None)
        if in_progress is None:
            in_progress = set()
            self._in_progress.keys = in_progress

        key = f"{qname}|{rdtype}"
        if key in in_progress:
            # Cycle detected (e.g. a nameserver hostname whose own
            # resolution depends on resolving itself, with no glue).
            return []

        in_progress.add(key)
        try:
            values, _, _, _ = self._resolve_iterative(qname, rdtype)
        except RecursionError:
            values = []
        finally:
            in_progress.discard(key)

        self._cache_values(qname, rdtype, values)
        return values

    def _cache_values(self, qname: str, rdtype: str, values: List[str]) -> None:
        """Store a result, using a short TTL for negative answers.

        Negative results (NXDOMAIN / NODATA / failed lookups) are cached for
        a much shorter TTL than positive answers: this avoids re-querying the
        same dead domain repeatedly within a scan, while still letting us pick
        it back up if it gets re-registered or the failure was transient.
        """
        ttl = POSITIVE_CACHE_TTL if values else NEGATIVE_CACHE_TTL
        self.cache.set(qname, rdtype, values, ttl=ttl)

    def _lookup_at(self, servers: List[str], qname: str, rdtype: str) -> List[str]:
        """Fetch `rdtype` for `qname` directly from already-known authoritative
        `servers`, falling back to a full iterative resolution if they don't
        answer. Results go through the same cache as `resolve()`.

        This is what lets `resolve_full` collect A, AAAA and NS with a single
        walk of the delegation chain rather than one walk per record type.
        """
        cached = self.cache.get(qname, rdtype)
        if cached is not None:
            return cached

        values: List[str] = []
        if servers:
            response = self._first_response(servers, qname, rdtype)
            if response is not None:
                if response.answer:
                    values, cname_target = self._extract_answer(response, rdtype)
                    if not values and cname_target:
                        values = self.resolve(cname_target, rdtype)
                    self._cache_values(qname, rdtype, values)
                    return values
                if not response.authority:
                    # Authoritative NODATA/NXDOMAIN: trust it, no need to walk.
                    self._cache_values(qname, rdtype, values)
                    return values

        # The known servers were unusable or handed back a referral (i.e. they
        # aren't authoritative for this name after all): do the full walk.
        return self.resolve(qname, rdtype)

    def resolve_full(self, domain: str) -> Dict[str, Any]:
        """Resolve A, AAAA and authoritative NS (+ their IPs) for domain."""
        domain = domain.rstrip(".") + "."
        cached = self.cache.get(domain, "FULL")
        if cached is not None:
            return cached

        # Walk the delegation chain once (via the NS lookup), then reuse the
        # resulting authoritative servers for the A and AAAA queries instead
        # of repeating the whole referral chain for each record type.
        ns_values, ns_info, zone, servers = self._resolve_iterative(
            domain, "NS", with_ns_info=True
        )
        a_records = self._lookup_at(servers, domain, "A")
        aaaa_records = self._lookup_at(servers, domain, "AAAA")

        # `zone` is the deepest delegated zone found while walking the
        # referral chain for the NS lookup above, i.e. the zone whose
        # authoritative nameservers actually serve this hostname. That is
        # exactly the registered/second-level domain, derived directly
        # from the real DNS delegation chain rather than from a static
        # public-suffix list.
        result = {
            "hostname": domain.rstrip("."),
            "zone": zone.rstrip(".") if zone else None,
            "a": sorted(set(a_records)),
            "aaaa": sorted(set(aaaa_records)),
            "nameserver_ips": [n for n in ns_info if n.get("ip")],
        }
        self.cache.set(domain, "FULL", result)
        return result

