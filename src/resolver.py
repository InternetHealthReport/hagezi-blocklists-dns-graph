"""A minimal iterative DNS resolver with an in-memory cache.

Instead of relying on a single (possibly rate-limited) recursive resolver,
this module performs the iterative resolution itself: starting at the root
servers, it follows referrals (NS records + glue) down to the authoritative
servers for a given name, exactly like a real recursive resolver would do
internally. Every answer (and every intermediate NS/glue lookup) is cached
in memory (keyed by name+type) so that a domain occurring in several
blocklists is never queried twice during a run.

This module is fully asyncio-based: DNS queries are non-blocking, so a
single event loop can have tens of thousands of lookups in flight at once
without paying for one OS thread per in-flight query. Because the whole
resolver runs on a single event loop (cooperative scheduling, no
preemption), the cache and zone-cut table do not need locks at all -- a
coroutine only yields control at explicit `await` points, so simple dict
reads/writes between awaits are inherently atomic.
"""

from __future__ import annotations

import asyncio
import contextvars
import random
import time
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

import dns.asyncquery
import dns.exception
import dns.flags
import dns.message
import dns.name
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

# How many servers to race concurrently for a single query. Rather than
# querying servers one at a time and retrying each before moving to the
# next (which can burn several times QUERY_TIMEOUT on a single slow/dead
# server), we fire queries at several candidate servers at once and take
# whichever answers first, cancelling the rest. This trades a small amount
# of extra query volume for a much lower worst-case latency per domain.
MAX_RACE = 3

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
    """A small in-memory cache, keyed by "name|rdtype".

    No locking is needed: the whole resolver runs on a single asyncio event
    loop, so plain dict operations between `await` points can never be
    interleaved with another coroutine's dict operations.
    """

    def __init__(self) -> None:
        self._data: Dict[str, Any] = {}

    @staticmethod
    def _key(name: str, rdtype: str) -> str:
        return f"{name.lower().rstrip('.')}|{rdtype.upper()}"

    def get(self, name: str, rdtype: str) -> Optional[Any]:
        entry = self._data.get(self._key(name, rdtype))
        if entry is None:
            return None
        if entry["expires"] < time.time():
            return None
        return entry["value"]

    def set(self, name: str, rdtype: str, value: Any, ttl: int = POSITIVE_CACHE_TTL) -> None:
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

    All I/O is async (`dns.asyncquery`), so a single `IterativeResolver`
    instance is meant to be driven by many concurrently-scheduled
    coroutines (e.g. via `asyncio.gather` bounded by a `Semaphore`) rather
    than by a thread pool.
    """

    def __init__(self) -> None:
        self.cache = MemoryCache()

        # Recursion/cycle guard: resolving the NS hostnames for a zone
        # sometimes requires resolving NS hostnames that are themselves
        # (glueless) subdomains of the zone being resolved, which can lead
        # to infinite recursion (e.g. ns.example.com being served by
        # ns.example.com itself, with no glue). We track the chain of
        # "name|rdtype" keys currently being resolved by the *current*
        # logical call chain using a ContextVar, which is automatically
        # copied (not shared) whenever a new Task is spawned (e.g. via
        # `asyncio.gather`), so unrelated concurrent lookups never see
        # each other's chains.
        self._resolving_chain: contextvars.ContextVar[FrozenSet[str]] = contextvars.ContextVar(
            "_resolving_chain", default=frozenset()
        )

        # Dedup in-flight lookups: if two coroutines ask for the exact same
        # "name|rdtype" concurrently (extremely common with blocklists,
        # e.g. many domains sharing the same nameserver or parent zone),
        # the second one awaits the first one's result instead of
        # re-running the whole referral walk.
        self._in_flight: Dict[str, "asyncio.Future[List[str]]"] = {}

        # Zone-cut cache: maps a delegated zone name (e.g. "com.") to the
        # IPs of its authoritative servers. Since thousands of domains in a
        # blocklist typically share only a handful of TLDs (and often the
        # same second-level zone), remembering "com." -> [gtld ips] lets us
        # jump straight past the root servers for every subsequent lookup
        # instead of re-walking the referral chain from scratch each time.
        # This is the single biggest speedup for bulk resolution.
        self._zone_cache: Dict[str, List[str]] = {}

    # -- low level -----------------------------------------------------
    async def _send_query(self, server_ip: str, qname: str, rdtype: str) -> Optional[dns.message.Message]:
        q = dns.message.make_query(qname, rdtype, want_dnssec=False)
        for _attempt in range(QUERY_RETRIES):
            try:
                response = await dns.asyncquery.udp(q, server_ip, timeout=QUERY_TIMEOUT)
                if response.flags & dns.flags.TC:
                    response = await dns.asyncquery.tcp(q, server_ip, timeout=QUERY_TIMEOUT)
                return response
            except (dns.exception.Timeout, OSError, dns.exception.DNSException):
                continue
        return None

    async def _first_response(
        self, servers: List[str], qname: str, rdtype: str
    ) -> Optional[dns.message.Message]:
        """Race up to `MAX_RACE` servers concurrently, returning the first
        usable response and cancelling the rest.

        Querying servers one at a time (and retrying each before moving on)
        means a single slow or dead server can cost several times
        QUERY_TIMEOUT before a working server is even tried. Racing several
        candidates at once bounds the worst case to roughly one timeout,
        at the cost of a bit of extra query volume against servers that
        turn out not to be needed.
        """
        if not servers:
            return None

        candidates = servers[:MAX_RACE]
        tasks = [asyncio.ensure_future(self._send_query(ip, qname, rdtype)) for ip in candidates]
        remaining_servers = servers[MAX_RACE:]

        try:
            pending = set(tasks)
            while pending:
                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    result = task.result()
                    if result is not None:
                        return result
            # None of the raced servers answered: fall back to the rest,
            # one at a time (rare path -- most zones have <= MAX_RACE
            # useful servers anyway).
            for ip in remaining_servers:
                result = await self._send_query(ip, qname, rdtype)
                if result is not None:
                    return result
            return None
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()

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

        This walks the query name's own suffixes from longest to shortest
        and does a plain dict lookup for each -- at most one lookup per
        label -- instead of scanning every entry of the zone cache.
        """
        candidates = self._suffixes(qname)
        for candidate in candidates:
            ips = self._zone_cache.get(candidate)
            if ips:
                return candidate, list(ips)
        return None

    def _cache_zone(self, zone: str, server_ips: List[str]) -> None:
        if not zone or not server_ips:
            return
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

    async def _resolve_iterative(
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

        async def ns_info(names: List[str]) -> List[Dict[str, str]]:
            return await self._ns_info(names) if with_ns_info else []

        for _ in range(MAX_REFERRALS):
            response = await self._first_response(servers, qname, rdtype)
            if response is None:
                return [], [], last_zone, servers

            # Direct answer.
            if response.answer:
                values, cname_target = self._extract_answer(response, rdtype)
                if not values and cname_target:
                    # Follow CNAME chain (fresh iterative lookup, cached).
                    values = await self.resolve(cname_target, rdtype)
                return values, await ns_info(last_ns_names), last_zone, servers

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
                return [], await ns_info(last_ns_names), last_zone, servers

            if zone in seen_zones:
                # Avoid infinite referral loops.
                return [], await ns_info(ns_names), last_zone, servers
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

            # No glue: resolve NS hostnames ourselves (cached), in parallel
            # rather than one at a time.
            resolved_lists = await asyncio.gather(
                *(self.resolve(ns_name, "A") for ns_name in ns_names[:MAX_GLUELESS_NS])
            )
            resolved_ips: List[str] = [ip for ips in resolved_lists for ip in ips]
            if not resolved_ips:
                return [], await ns_info(ns_names), last_zone, servers
            servers = resolved_ips
            self._cache_zone(zone, servers)

        return [], [], last_zone, servers

    async def _ns_info(self, ns_names: List[str]) -> List[Dict[str, str]]:
        # Resolve every nameserver hostname's A and AAAA addresses
        # concurrently instead of one at a time.
        a_results, aaaa_results = await asyncio.gather(
            asyncio.gather(*(self.resolve(name, "A") for name in ns_names)),
            asyncio.gather(*(self.resolve(name, "AAAA") for name in ns_names)),
        )
        info = []
        for name, a_ips, aaaa_ips in zip(ns_names, a_results, aaaa_results):
            ips = list(a_ips) + list(aaaa_ips)
            if ips:
                info.extend({"name": name, "ip": ip} for ip in ips)
            else:
                info.append({"name": name, "ip": None})
        return info

    # -- public, cached entry point --------------------------------------
    async def resolve(self, qname: str, rdtype: str) -> List[str]:
        qname = qname.rstrip(".") + "."
        cached = self.cache.get(qname, rdtype)
        if cached is not None:
            return cached

        key = f"{qname}|{rdtype}"

        chain = self._resolving_chain.get()
        if key in chain:
            # Cycle detected (e.g. a nameserver hostname whose own
            # resolution depends on resolving itself, with no glue).
            return []

        # If another coroutine is already resolving the exact same
        # name+type, piggyback on its result instead of duplicating the
        # work (very common: many domains share a nameserver or parent
        # zone).
        existing = self._in_flight.get(key)
        if existing is not None:
            return await existing

        loop = asyncio.get_event_loop()
        future: "asyncio.Future[List[str]]" = loop.create_future()
        self._in_flight[key] = future
        token = self._resolving_chain.set(chain | {key})
        try:
            values, _, _, _ = await self._resolve_iterative(qname, rdtype)
        except RecursionError:
            values = []
        finally:
            self._resolving_chain.reset(token)
            self._in_flight.pop(key, None)

        self._cache_values(qname, rdtype, values)
        if not future.done():
            future.set_result(values)
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

    async def _lookup_at(self, servers: List[str], qname: str, rdtype: str) -> List[str]:
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
            response = await self._first_response(servers, qname, rdtype)
            if response is not None:
                if response.answer:
                    values, cname_target = self._extract_answer(response, rdtype)
                    if not values and cname_target:
                        values = await self.resolve(cname_target, rdtype)
                    self._cache_values(qname, rdtype, values)
                    return values
                if not response.authority:
                    # Authoritative NODATA/NXDOMAIN: trust it, no need to walk.
                    self._cache_values(qname, rdtype, values)
                    return values

        # The known servers were unusable or handed back a referral (i.e. they
        # aren't authoritative for this name after all): do the full walk.
        return await self.resolve(qname, rdtype)

    async def resolve_full(self, domain: str, with_ns_info: bool = True) -> Dict[str, Any]:
        """Resolve A, AAAA and (optionally) authoritative NS + their IPs for
        `domain`.

        `with_ns_info` controls whether nameserver hostnames are also
        resolved to IPs: this is a large source of extra query fan-out
        (one more lookup per nameserver, per domain) that many callers
        don't actually need. Set it to False to roughly halve the number
        of DNS round trips per domain when nameserver IPs aren't required.
        """
        domain = domain.rstrip(".") + "."
        cache_key = "FULL" if with_ns_info else "FULL_NO_NS"
        cached = self.cache.get(domain, cache_key)
        if cached is not None:
            return cached

        # Walk the delegation chain once (via the NS lookup), then reuse the
        # resulting authoritative servers for the A and AAAA queries instead
        # of repeating the whole referral chain for each record type.
        ns_values, ns_info, zone, servers = await self._resolve_iterative(
            domain, "NS", with_ns_info=with_ns_info
        )

        # A and AAAA share the same authoritative servers, so fetch them
        # concurrently instead of one after the other.
        a_records, aaaa_records = await asyncio.gather(
            self._lookup_at(servers, domain, "A"),
            self._lookup_at(servers, domain, "AAAA"),
        )

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
        self.cache.set(domain, cache_key, result)
        return result

