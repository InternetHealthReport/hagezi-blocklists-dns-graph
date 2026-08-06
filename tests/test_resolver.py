"""Tests for the iterative DNS resolver.

These tests monkeypatch `IterativeResolver._send_query` so no real network
traffic is generated; they build fake `dns.message.Message` responses that
mimic what real root/TLD/authoritative servers would answer, and check that
the iterative-referral-following logic in `resolver.py` behaves correctly
(including the fix for infinite recursion on glueless nameserver cycles).

`resolve()` / `resolve_full()` (and the low-level `_send_query`) are all
`async def` coroutines, so every test below runs its assertions inside
`asyncio.run(...)`, and the fake `_send_query` replacements are themselves
`async def` functions so they can be awaited exactly like the real one.
"""

from __future__ import annotations

import asyncio

import dns.message

from src.resolver import MAX_RACE, NEGATIVE_CACHE_TTL, POSITIVE_CACHE_TTL, IterativeResolver


def _make_response(text: str) -> dns.message.Message:
    """Build a dns.message.Message from a small hand-written zone-file-like
    text block, used to fake server responses in tests."""
    header = (
        "id 1\n"
        "opcode QUERY\n"
        "rcode NOERROR\n"
        "flags QR AA\n"
    )
    return dns.message.from_text(header + text)


def _referral_response(zone: str, ns_names: list[str], glue: dict[str, str] | None = None) -> dns.message.Message:
    authority = "\n".join(f"{zone} 3600 IN NS {ns}" for ns in ns_names)
    additional = ""
    if glue:
        additional = "\n".join(f"{name} 3600 IN A {ip}" for name, ip in glue.items())
    text = ";AUTHORITY\n" + authority
    if additional:
        text += "\n;ADDITIONAL\n" + additional
    return _make_response(text)


def _answer_response(qname: str, rdtype: str, values: list[str]) -> dns.message.Message:
    text = ";ANSWER\n" + "\n".join(f"{qname} 3600 IN {rdtype} {v}" for v in values)
    return _make_response(text)


def _nodata_response() -> dns.message.Message:
    return _make_response("")


def test_resolve_returns_direct_answer(monkeypatch):
    resolver = IterativeResolver()

    async def fake_send(server_ip, qname, rdtype):
        return _answer_response("example.com.", "A", ["1.2.3.4"])

    monkeypatch.setattr(resolver, "_send_query", fake_send)

    result = asyncio.run(resolver.resolve("example.com", "A"))
    assert result == ["1.2.3.4"]


def test_resolve_follows_referral_with_glue(monkeypatch):
    """Root servers hand back a referral (with glue) to the TLD servers,
    which then answer directly.

    `_first_response` races up to `MAX_RACE` candidate servers concurrently
    for every hop, so more than one query can be sent per hop even though
    only the first answer actually matters -- the assertions below account
    for that instead of assuming exactly one query per hop.
    """
    resolver = IterativeResolver()

    seen_ips: list[str] = []

    async def fake_send(server_ip, qname, rdtype):
        seen_ips.append(server_ip)
        if server_ip != "192.0.2.1":
            # Root (or any non-glue) server refers to the TLD servers.
            return _referral_response("com.", ["a.gtld-servers.net."], glue={"a.gtld-servers.net.": "192.0.2.1"})
        # The glued TLD server gives the final answer.
        return _answer_response("example.com.", "A", ["5.6.7.8"])

    monkeypatch.setattr(resolver, "_send_query", fake_send)

    result = asyncio.run(resolver.resolve("example.com", "A"))
    assert result == ["5.6.7.8"]
    # The referral hop races at most MAX_RACE root servers, then a single
    # query is sent to the glued TLD server.
    assert 2 <= len(seen_ips) <= MAX_RACE + 1
    assert "192.0.2.1" in seen_ips


def test_resolve_reuses_cached_zone_cut(monkeypatch):
    """A second domain under an already-seen TLD must skip the root servers."""
    resolver = IterativeResolver()

    seen_servers: list[str] = []

    async def fake_send(server_ip, qname, rdtype):
        seen_servers.append(server_ip)
        if server_ip != "192.0.2.1":
            return _referral_response(
                "com.", ["a.gtld-servers.net."], glue={"a.gtld-servers.net.": "192.0.2.1"}
            )
        return _answer_response(qname, "A", ["5.6.7.8"])

    monkeypatch.setattr(resolver, "_send_query", fake_send)

    assert asyncio.run(resolver.resolve("first.com", "A")) == ["5.6.7.8"]
    seen_servers.clear()
    assert asyncio.run(resolver.resolve("second.com", "A")) == ["5.6.7.8"]
    # The "com." zone cut is cached, so the walk starts at the TLD server.
    assert seen_servers == ["192.0.2.1"]


def test_resolve_no_answer_and_no_referral_returns_empty(monkeypatch):
    resolver = IterativeResolver()

    async def fake_send(server_ip, qname, rdtype):
        return _nodata_response()

    monkeypatch.setattr(resolver, "_send_query", fake_send)

    result = asyncio.run(resolver.resolve("nonexistent.example", "A"))
    assert result == []


def test_negative_results_use_a_shorter_ttl(monkeypatch):
    """Dead domains must not be pinned in the cache as long as live ones."""
    resolver = IterativeResolver()

    recorded: dict[str, int] = {}
    original_set = resolver.cache.set

    def spy_set(name, rdtype, value, ttl=POSITIVE_CACHE_TTL):
        recorded[rdtype] = ttl
        return original_set(name, rdtype, value, ttl=ttl)

    async def fake_send(server_ip, qname, rdtype):
        return _nodata_response()

    monkeypatch.setattr(resolver.cache, "set", spy_set)
    monkeypatch.setattr(resolver, "_send_query", fake_send)

    assert asyncio.run(resolver.resolve("nonexistent.example", "A")) == []
    assert recorded["A"] == NEGATIVE_CACHE_TTL


def test_resolve_returns_empty_when_all_queries_fail(monkeypatch):
    resolver = IterativeResolver()

    async def fake_send(server_ip, qname, rdtype):
        return None

    monkeypatch.setattr(resolver, "_send_query", fake_send)

    result = asyncio.run(resolver.resolve("example.com", "A"))
    assert result == []


def test_resolve_caches_results_across_calls(monkeypatch):
    resolver = IterativeResolver()

    call_count = {"n": 0}

    async def fake_send(server_ip, qname, rdtype):
        call_count["n"] += 1
        return _answer_response("example.com.", "A", ["1.2.3.4"])

    monkeypatch.setattr(resolver, "_send_query", fake_send)

    async def run_both():
        first = await resolver.resolve("example.com", "A")
        after_first = call_count["n"]
        second = await resolver.resolve("example.com", "A")
        return first, second, after_first

    first, second, after_first = asyncio.run(run_both())

    assert first == second == ["1.2.3.4"]
    # `_first_response` races up to MAX_RACE root servers concurrently for the
    # first call, but the second call must be served entirely from cache,
    # issuing no additional queries at all.
    assert 1 <= after_first <= MAX_RACE
    assert call_count["n"] == after_first


def test_resolve_glueless_nameserver_cycle_does_not_hang(monkeypatch):
    """Regression test for the infinite-recursion bug: a nameserver whose own
    resolution loops back onto itself (no glue) must terminate instead of
    hanging forever."""
    resolver = IterativeResolver()

    async def fake_send(server_ip, qname, rdtype):
        # Every query, regardless of target, refers to the very same
        # glueless nameserver -- a pathological but real-world-possible
        # configuration.
        return _referral_response("example.com.", ["ns.example.com."], glue=None)

    monkeypatch.setattr(resolver, "_send_query", fake_send)

    # Must return (not hang) and yield no addresses since it never resolves.
    result = asyncio.run(resolver.resolve("example.com", "A"))
    assert result == []


def test_resolve_full_returns_expected_shape(monkeypatch):
    resolver = IterativeResolver()

    async def fake_send(server_ip, qname, rdtype):
        if rdtype == "A" and qname.rstrip(".") == "example.com":
            return _answer_response("example.com.", "A", ["1.2.3.4"])
        if rdtype == "AAAA" and qname.rstrip(".") == "example.com":
            return _answer_response("example.com.", "AAAA", ["::1"])
        if rdtype == "NS":
            return _referral_response(
                "example.com.",
                ["ns1.example.com."],
                glue={"ns1.example.com.": "9.9.9.9"},
            )
        if rdtype == "A" and qname.rstrip(".") == "ns1.example.com":
            return _answer_response("ns1.example.com.", "A", ["9.9.9.9"])
        return _nodata_response()

    monkeypatch.setattr(resolver, "_send_query", fake_send)

    result = asyncio.run(resolver.resolve_full("example.com"))

    assert result["hostname"] == "example.com"
    assert result["zone"] == "example.com"
    assert result["a"] == ["1.2.3.4"]
    assert result["aaaa"] == ["::1"]
    assert "nameserver_ips" in result

