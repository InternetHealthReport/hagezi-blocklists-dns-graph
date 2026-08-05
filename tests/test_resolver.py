"""Tests for the iterative DNS resolver.

These tests monkeypatch `IterativeResolver._send_query` so no real network
traffic is generated; they build fake `dns.message.Message` responses that
mimic what real root/TLD/authoritative servers would answer, and check that
the iterative-referral-following logic in `resolver.py` behaves correctly
(including the fix for infinite recursion on glueless nameserver cycles).
"""

from __future__ import annotations

import dns.message

from src.resolver import NEGATIVE_CACHE_TTL, POSITIVE_CACHE_TTL, IterativeResolver


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

    monkeypatch.setattr(
        resolver,
        "_send_query",
        lambda server_ip, qname, rdtype: _answer_response("example.com.", "A", ["1.2.3.4"]),
    )

    result = resolver.resolve("example.com", "A")
    assert result == ["1.2.3.4"]


def test_resolve_follows_referral_with_glue(monkeypatch):
    resolver = IterativeResolver()

    call_count = {"n": 0}

    def fake_send(server_ip, qname, rdtype):
        call_count["n"] += 1
        if call_count["n"] == 1:
            # Root refers to the TLD servers, with glue.
            return _referral_response("com.", ["a.gtld-servers.net."], glue={"a.gtld-servers.net.": "192.0.2.1"})
        # Second query (to the glued TLD server) gives the final answer.
        return _answer_response("example.com.", "A", ["5.6.7.8"])

    monkeypatch.setattr(resolver, "_send_query", fake_send)

    result = resolver.resolve("example.com", "A")
    assert result == ["5.6.7.8"]
    # One query for the referral, one for the final answer. `resolve()` never
    # asks for nameserver details, so no extra address lookups happen.
    assert call_count["n"] == 2


def test_resolve_reuses_cached_zone_cut(monkeypatch):
    """A second domain under an already-seen TLD must skip the root servers."""
    resolver = IterativeResolver()

    seen_servers: list[str] = []

    def fake_send(server_ip, qname, rdtype):
        seen_servers.append(server_ip)
        if server_ip != "192.0.2.1":
            return _referral_response(
                "com.", ["a.gtld-servers.net."], glue={"a.gtld-servers.net.": "192.0.2.1"}
            )
        return _answer_response(qname, "A", ["5.6.7.8"])

    monkeypatch.setattr(resolver, "_send_query", fake_send)

    assert resolver.resolve("first.com", "A") == ["5.6.7.8"]
    seen_servers.clear()
    assert resolver.resolve("second.com", "A") == ["5.6.7.8"]
    # The "com." zone cut is cached, so the walk starts at the TLD server.
    assert seen_servers == ["192.0.2.1"]


def test_resolve_no_answer_and_no_referral_returns_empty(monkeypatch):
    resolver = IterativeResolver()

    monkeypatch.setattr(resolver, "_send_query", lambda server_ip, qname, rdtype: _nodata_response())

    result = resolver.resolve("nonexistent.example", "A")
    assert result == []


def test_negative_results_use_a_shorter_ttl(monkeypatch):
    """Dead domains must not be pinned in the cache as long as live ones."""
    resolver = IterativeResolver()

    recorded: dict[str, int] = {}
    original_set = resolver.cache.set

    def spy_set(name, rdtype, value, ttl=POSITIVE_CACHE_TTL):
        recorded[rdtype] = ttl
        return original_set(name, rdtype, value, ttl=ttl)

    monkeypatch.setattr(resolver.cache, "set", spy_set)
    monkeypatch.setattr(resolver, "_send_query", lambda server_ip, qname, rdtype: _nodata_response())

    assert resolver.resolve("nonexistent.example", "A") == []
    assert recorded["A"] == NEGATIVE_CACHE_TTL


def test_resolve_returns_empty_when_all_queries_fail(monkeypatch):
    resolver = IterativeResolver()

    monkeypatch.setattr(resolver, "_send_query", lambda server_ip, qname, rdtype: None)

    result = resolver.resolve("example.com", "A")
    assert result == []


def test_resolve_caches_results_across_calls(monkeypatch):
    resolver = IterativeResolver()

    call_count = {"n": 0}

    def fake_send(server_ip, qname, rdtype):
        call_count["n"] += 1
        return _answer_response("example.com.", "A", ["1.2.3.4"])

    monkeypatch.setattr(resolver, "_send_query", fake_send)

    first = resolver.resolve("example.com", "A")
    second = resolver.resolve("example.com", "A")

    assert first == second == ["1.2.3.4"]
    # Only the first call should have actually hit the network.
    assert call_count["n"] == 1


def test_resolve_glueless_nameserver_cycle_does_not_hang(monkeypatch):
    """Regression test for the infinite-recursion bug: a nameserver whose own
    resolution loops back onto itself (no glue) must terminate instead of
    hanging forever."""
    resolver = IterativeResolver()

    def fake_send(server_ip, qname, rdtype):
        # Every query, regardless of target, refers to the very same
        # glueless nameserver -- a pathological but real-world-possible
        # configuration.
        return _referral_response("example.com.", ["ns.example.com."], glue=None)

    monkeypatch.setattr(resolver, "_send_query", fake_send)

    # Must return (not hang) and yield no addresses since it never resolves.
    result = resolver.resolve("example.com", "A")
    assert result == []


def test_resolve_full_returns_expected_shape(monkeypatch):
    resolver = IterativeResolver()

    def fake_send(server_ip, qname, rdtype):
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

    result = resolver.resolve_full("example.com")

    assert result["hostname"] == "example.com"
    assert result["zone"] == "example.com"
    assert result["a"] == ["1.2.3.4"]
    assert result["aaaa"] == ["::1"]
    assert "nameserver_ips" in result
    assert "nameservers" in result

