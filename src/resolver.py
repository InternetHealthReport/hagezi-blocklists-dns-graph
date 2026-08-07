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
import functools
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

# Base delay (seconds) used to compute randomized backoff between retry
# attempts within `_send_query`. Retrying immediately after a timeout/error
# means every in-flight domain resolution retries in lockstep, producing
# the same bursty all-at-once traffic pattern that got rate-limited in the
# first place. Adding a small random jitter delay before each retry spreads
# retries out over time instead, which is much friendlier to any
# server-side (or CI-egress-side) rate limiting.
RETRY_BASE_DELAY = 0.1
RETRY_MAX_DELAY = 1.0

# How many servers to race concurrently for a single query. Rather than
# querying servers one at a time and retrying each before moving to the
# next (which can burn several times QUERY_TIMEOUT on a single slow/dead
# server), we fire queries at several candidate servers at once and take
# whichever answers first, cancelling the rest. This trades a small amount
# of extra query volume for a much lower worst-case latency per domain.
MAX_RACE = 5

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


class ResolverStats:
    """Lightweight counters/timers describing what a resolver run spent its
    time and queries on.

    No locking is needed here either: like the rest of this module, all
    increments happen on a single asyncio event loop between `await`
    points, so plain int/float mutation is inherently safe.
    """

    def __init__(self) -> None:
        # Wall-clock start time, used to compute real throughput
        # (domains/sec) across the whole run. This is distinct from
        # `domain_time_total`/`avg_domain_s` below, which sum each
        # individual domain's own latency: since domains are resolved
        # concurrently (bounded by a semaphore in main.py), the sum of
        # per-domain latencies can be many times the actual wall-clock
        # duration of the run, so the two numbers must not be confused.
        self.start_time = time.monotonic()

        # Top-level name+type cache (the one consulted by `resolve()` /
        # `_lookup_at()`).
        self.cache_hits = 0
        self.cache_misses = 0

        # Zone-cut cache (`_best_cached_zone` / `_cache_zone`), i.e. how
        # often we could skip straight to a known TLD/zone's servers
        # instead of starting the referral walk from the root.
        self.zone_cache_hits = 0
        self.zone_cache_misses = 0

        # In-flight de-duplication: another coroutine was already resolving
        # the exact same name+type, so this call piggybacked on it instead
        # of issuing its own queries.
        self.dedup_hits = 0

        # Low-level wire queries, one increment per server contacted.
        self.queries_sent = 0
        self.queries_answered = 0
        self.query_timeouts = 0  # dns.exception.Timeout
        self.query_errors = 0  # OSError / other dns.exception.DNSException
        self.query_time_total = 0.0  # sum of per-query wall-clock seconds

        # Referral-walk bookkeeping.
        self.referrals_followed = 0
        self.glueless_lookups = 0
        self.nxdomain_count = 0  # no answer and no further delegation
        self.referral_loops = 0  # zone seen twice -> loop guard triggered

        # Whole-domain (resolve_full) bookkeeping.
        self.domains_resolved = 0
        self.domain_timeouts = 0
        self.domain_time_total = 0.0

    def record_query(self, elapsed: float, outcome: str) -> None:
        """Record the outcome of a single `_send_query` attempt.

        `outcome` is one of "answered", "timeout", "error".
        """
        self.queries_sent += 1
        self.query_time_total += elapsed
        if outcome == "answered":
            self.queries_answered += 1
        elif outcome == "timeout":
            self.query_timeouts += 1
        else:
            self.query_errors += 1

    def record_domain(self, elapsed: float, timed_out: bool = False) -> None:
        self.domains_resolved += 1
        self.domain_time_total += elapsed
        if timed_out:
            self.domain_timeouts += 1

    def snapshot(self) -> Dict[str, Any]:
        """Return a plain dict of all counters plus a few derived averages,
        suitable for logging or dumping as JSON."""
        avg_query_ms = (
            (self.query_time_total / self.queries_sent) * 1000 if self.queries_sent else 0.0
        )
        # `avg_domain_s` is the average of each domain's own resolution
        # latency (time spent inside `resolve_full` for that one domain).
        # Because domains are resolved concurrently (bounded by a semaphore
        # in main.py), this is NOT the same as "total wall-clock time /
        # domains resolved" -- summing per-domain latencies double (or
        # N-times) counts time that overlapped across concurrent domains.
        avg_domain_s = (
            self.domain_time_total / self.domains_resolved if self.domains_resolved else 0.0
        )
        # Real wall-clock elapsed time since this ResolverStats was created,
        # and the actual throughput that implies -- this is the number that
        # reflects how long a run actually took / will take, unlike
        # `avg_domain_s` above.
        elapsed_wall_s = time.monotonic() - self.start_time
        domains_per_sec = (
            self.domains_resolved / elapsed_wall_s if elapsed_wall_s > 0 else 0.0
        )
        total_cache_lookups = self.cache_hits + self.cache_misses
        cache_hit_rate = (
            self.cache_hits / total_cache_lookups if total_cache_lookups else 0.0
        )
        return {
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_hit_rate": cache_hit_rate,
            "zone_cache_hits": self.zone_cache_hits,
            "zone_cache_misses": self.zone_cache_misses,
            "dedup_hits": self.dedup_hits,
            "queries_sent": self.queries_sent,
            "queries_answered": self.queries_answered,
            "query_timeouts": self.query_timeouts,
            "query_errors": self.query_errors,
            "avg_query_ms": avg_query_ms,
            "referrals_followed": self.referrals_followed,
            "glueless_lookups": self.glueless_lookups,
            "nxdomain_count": self.nxdomain_count,
            "referral_loops": self.referral_loops,
            "domains_resolved": self.domains_resolved,
            "domain_timeouts": self.domain_timeouts,
            "avg_domain_s": avg_domain_s,
            "elapsed_wall_s": elapsed_wall_s,
            "domains_per_sec": domains_per_sec,
        }

    def report(self) -> str:
        """Render a short human-readable multi-line summary."""
        s = self.snapshot()
        lines = [
            "Resolver stats:",
            f"  name+type cache : {s['cache_hits']} hits / {s['cache_misses']} misses "
            f"({s['cache_hit_rate'] * 100:.1f}% hit rate)",
            f"  zone-cut cache  : {s['zone_cache_hits']} hits / {s['zone_cache_misses']} misses",
            f"  dedup piggybacks: {s['dedup_hits']}",
            f"  wire queries    : {s['queries_sent']} sent, {s['queries_answered']} answered, "
            f"{s['query_timeouts']} timed out, {s['query_errors']} errored "
            f"(avg {s['avg_query_ms']:.1f} ms/query)",
            f"  referral walk   : {s['referrals_followed']} referrals, "
            f"{s['glueless_lookups']} glueless NS lookups, {s['referral_loops']} loops detected, "
            f"{s['nxdomain_count']} NXDOMAIN/NODATA",
            f"  domains         : {s['domains_resolved']} resolved, {s['domain_timeouts']} timed out "
            f"(avg {s['avg_domain_s']:.3f} s/domain latency, concurrent)",
            f"  throughput      : {s['elapsed_wall_s']:.1f} s wall-clock, "
            f"{s['domains_per_sec']:.1f} domains/sec",
        ]
        return "\n".join(lines)


class MemoryCache:
    """A small in-memory cache, keyed by "name|rdtype".

    No locking is needed: the whole resolver runs on a single asyncio event
    loop, so plain dict operations between `await` points can never be
    interleaved with another coroutine's dict operations.
    """

    def __init__(self, stats: Optional[ResolverStats] = None) -> None:
        self._data: Dict[str, Any] = {}
        self._stats = stats

    @staticmethod
    def _key(name: str, rdtype: str) -> str:
        return f"{name.lower().rstrip('.')}|{rdtype.upper()}"

    def get(self, name: str, rdtype: str) -> Optional[Any]:
        entry = self._data.get(self._key(name, rdtype))
        if entry is None or entry["expires"] < time.time():
            if self._stats is not None:
                self._stats.cache_misses += 1
            return None
        if self._stats is not None:
            self._stats.cache_hits += 1
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
        self.stats = ResolverStats()
        self.cache = MemoryCache(stats=self.stats)

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

        # Dedup + cache in-flight/completed NS referral walks performed by
        # `resolve_full` (see `_resolve_ns_walk`). Kept separate from
        # `_in_flight` above because it stores a different result shape
        # (the full (values, ns_info, zone, servers) tuple, not just a list
        # of record values).
        self._ns_walk_in_flight: Dict[
            str, "asyncio.Future[Tuple[List[str], List[Dict[str, str]], Optional[str], List[str]]]"
        ] = {}

        # Zone-cut cache: maps a delegated zone name (e.g. "com.") to the
        # IPs of its authoritative servers. Since thousands of domains in a
        # blocklist typically share only a handful of TLDs (and often the
        # same second-level zone), remembering "com." -> [gtld ips] lets us
        # jump straight past the root servers for every subsequent lookup
        # instead of re-walking the referral chain from scratch each time.
        # This is the single biggest speedup for bulk resolution.
        self._zone_cache: Dict[str, List[str]] = {}

        # Cache of completed NS referral walks performed by `resolve_full`
        # via `_resolve_ns_walk` (see `_ns_walk_in_flight` above). Unlike
        # the top-level `MemoryCache`, entries here store the full
        # (values, ns_info, zone, servers) tuple, keyed by
        # "domain|NS|with_ns_info", since `resolve_full` needs both the
        # zone/servers (to reuse for the A/AAAA `_lookup_at` calls) and the
        # ns_info (which is only computed when `with_ns_info` is true, so
        # it must be part of the cache key to avoid serving a cached entry
        # built without ns_info to a caller that requested it).
        self._ns_walk_cache: Dict[
            str, Tuple[List[str], List[Dict[str, str]], Optional[str], List[str], float]
        ] = {}

    # -- low level -----------------------------------------------------
    async def _send_query(self, server_ip: str, qname: str, rdtype: str) -> Optional[dns.message.Message]:
        q = dns.message.make_query(qname, rdtype, want_dnssec=False)
        last_outcome = "error"
        for attempt in range(QUERY_RETRIES):
            if attempt > 0:
                # Jittered backoff before each retry: retrying immediately
                # after a timeout/error means every in-flight domain
                # resolution retries in lockstep, producing the same
                # bursty all-at-once traffic pattern that likely got
                # rate-limited in the first place (see RETRY_BASE_DELAY
                # above). Exponential-ish growth (scaled by attempt number)
                # capped at RETRY_MAX_DELAY, with full jitter so concurrent
                # retries don't line back up with each other.
                delay = min(RETRY_MAX_DELAY, RETRY_BASE_DELAY * (2 ** (attempt - 1)))
                await asyncio.sleep(random.uniform(0, delay))
            start = time.monotonic()
            try:
                response = await dns.asyncquery.udp(q, server_ip, timeout=QUERY_TIMEOUT)
                if response.flags & dns.flags.TC:
                    response = await dns.asyncquery.tcp(q, server_ip, timeout=QUERY_TIMEOUT)
                self.stats.record_query(time.monotonic() - start, "answered")
                return response
            except dns.exception.Timeout:
                self.stats.record_query(time.monotonic() - start, "timeout")
                last_outcome = "timeout"
                continue
            except (OSError, dns.exception.DNSException):
                self.stats.record_query(time.monotonic() - start, "error")
                last_outcome = "error"
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
    @functools.lru_cache(maxsize=65536)
    def _suffixes(qname: str) -> Tuple[str, ...]:
        """Return the ancestor zone names of `qname`, longest first.

        e.g. "a.b.example.com." -> ["a.b.example.com.", "b.example.com.",
        "example.com.", "com."]. Used to probe the zone-cut cache with a
        handful of direct dict lookups instead of scanning every known zone.

        This is a pure function of `qname` (it never touches any resolver
        state) and is called at least once per query attempt -- including
        every referral hop and every glueless NS lookup -- so across a
        million-domain run it ends up being invoked many millions of times.
        Parsing/serializing `dns.name.Name` objects on every single call
        was showing up as measurable CPU overhead; since blocklists share
        huge numbers of common suffixes (most domains share a TLD, many
        share a whole parent zone), an `lru_cache` turns most of those
        calls into a dict lookup instead of repeated DNS-name parsing.
        """
        try:
            name = dns.name.from_text(qname)
        except dns.exception.DNSException:
            return ()
        labels = name.labels
        # Keep the trailing root label so the generated names are absolute
        # ("com." rather than "com") and match the zone-cache keys, which
        # come straight from the wire format.
        return tuple(
            dns.name.Name(labels[i:]).to_text() for i in range(len(labels) - 1)
        )

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
                self.stats.zone_cache_hits += 1
                return candidate, list(ips)
        self.stats.zone_cache_misses += 1
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
                self.stats.nxdomain_count += 1
                return [], await ns_info(last_ns_names), last_zone, servers

            if zone in seen_zones:
                # Avoid infinite referral loops.
                self.stats.referral_loops += 1
                return [], await ns_info(ns_names), last_zone, servers
            seen_zones.add(zone)
            last_ns_names = ns_names
            last_zone = zone
            self.stats.referrals_followed += 1

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
            self.stats.glueless_lookups += 1
            resolved_lists = await asyncio.gather(
                *(self.resolve(ns_name, "A") for ns_name in ns_names[:MAX_GLUELESS_NS])
            )
            resolved_ips: List[str] = [ip for ips in resolved_lists for ip in ips]
            if not resolved_ips:
                return [], await ns_info(ns_names), last_zone, servers
            servers = resolved_ips
            self._cache_zone(zone, servers)

        return [], [], last_zone, servers

    async def _resolve_ns_walk(
        self, domain: str, with_ns_info: bool
    ) -> Tuple[List[str], List[Dict[str, str]], Optional[str], List[str]]:
        """Cached + deduped wrapper around `_resolve_iterative(domain, "NS")`.

        `resolve_full` used to call `_resolve_iterative` directly for its NS
        lookup, which bypassed both the top-level `MemoryCache` and the
        `_in_flight` dedup that `resolve()` benefits from. That meant a
        domain occurring more than once in a merged blocklist (or resolved
        concurrently more than once) would re-walk the whole NS referral
        chain from scratch every time -- unlike its A/AAAA counterparts,
        which already go through the cached `_lookup_at()`. This wrapper
        closes that gap by caching (and deduping in-flight) the full
        (values, ns_info, zone, servers) tuple, keyed by
        "domain|NS|with_ns_info" so a cached entry built without ns_info is
        never handed back to a caller that actually requested it.
        """
        key = f"{domain}|NS|{with_ns_info}"

        cached = self._ns_walk_cache.get(key)
        if cached is not None:
            values, ns_info, zone, servers, expires = cached
            if expires >= time.time():
                self.stats.cache_hits += 1
                return values, ns_info, zone, servers
            self._ns_walk_cache.pop(key, None)
        self.stats.cache_misses += 1

        existing = self._ns_walk_in_flight.get(key)
        if existing is not None:
            # See `resolve()` for why `asyncio.shield` is needed here: this
            # future is shared by every coroutine currently walking the
            # exact same NS chain, and our own cancellation must not
            # propagate to them.
            self.stats.dedup_hits += 1
            return await asyncio.shield(existing)

        loop = asyncio.get_event_loop()
        future: "asyncio.Future[Tuple[List[str], List[Dict[str, str]], Optional[str], List[str]]]" = (
            loop.create_future()
        )
        self._ns_walk_in_flight[key] = future
        try:
            result = await self._resolve_iterative(domain, "NS", with_ns_info=with_ns_info)
        except Exception as exc:
            if not future.done():
                future.set_exception(exc)
            raise
        finally:
            self._ns_walk_in_flight.pop(key, None)

        values, ns_info, zone, servers = result
        ttl = POSITIVE_CACHE_TTL if values or zone else NEGATIVE_CACHE_TTL
        self._ns_walk_cache[key] = (values, ns_info, zone, servers, time.time() + ttl)
        if not future.done():
            future.set_result(result)
        return result

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
            # `existing` is a single Future shared by every coroutine
            # currently resolving this exact name+type. If we awaited it
            # directly, cancelling *this* caller (e.g. via the per-domain
            # `asyncio.wait_for` timeout in main.py) would cancel the
            # future itself, which would incorrectly propagate
            # CancelledError to every other unrelated coroutine piggybacking
            # on the same lookup. `asyncio.shield` ensures our own
            # cancellation only detaches us from the future (still raising
            # CancelledError here, as expected) without cancelling it for
            # everyone else.
            self.stats.dedup_hits += 1
            return await asyncio.shield(existing)

        loop = asyncio.get_event_loop()
        future: "asyncio.Future[List[str]]" = loop.create_future()
        self._in_flight[key] = future
        token = self._resolving_chain.set(chain | {key})
        try:
            # Protect the full iterative walk with a timeout so a bug or
            # unexpected hang in the lower-level code doesn't leave callers
            # awaiting an in-flight future forever. We pick a conservative
            # timeout based on the per-query timeout/retries and a small
            # multiplier for referral walks.
            total_timeout = max(10.0, QUERY_TIMEOUT * (QUERY_RETRIES + 1) * 5)
            try:
                values, _, _, _ = await asyncio.wait_for(
                    self._resolve_iterative(qname, rdtype), timeout=total_timeout
                )
            except asyncio.TimeoutError:
                values = []
            except RecursionError:
                values = []
        except Exception as exc:
            # Ensure we propagate unexpected exceptions to any other
            # coroutines that were awaiting the same in-flight future:
            if not future.done():
                future.set_exception(exc)
            raise
        finally:
            self._resolving_chain.reset(token)
            self._in_flight.pop(key, None)

        # Cache and resolve any waiters.
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
        start = time.monotonic()
        timed_out = False

        try:
            # Walk the delegation chain once (via the NS lookup), then reuse
            # the resulting authoritative servers for the A and AAAA queries
            # instead of repeating the whole referral chain for each record
            # type.
            ns_values, ns_info, zone, servers = await self._resolve_ns_walk(
                domain, with_ns_info
            )

            # A and AAAA share the same authoritative servers, so fetch them
            # concurrently instead of one after the other.
            a_records, aaaa_records = await asyncio.gather(
                self._lookup_at(servers, domain, "A"),
                self._lookup_at(servers, domain, "AAAA"),
            )
        except asyncio.TimeoutError:
            timed_out = True
            raise
        finally:
            self.stats.record_domain(time.monotonic() - start, timed_out=timed_out)

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
        return result

