"""Tests for the iterative DNS resolver.

These tests monkeypatch `IterativeResolver._send_query` so no real network
traffic is generated; they build fake `dns.message.Message` responses that
mimic what real root/TLD/authoritative servers would answer, and check that
the iterative-referral-following logic in `resolver.py` behaves correctly
(including the fix for infinite recursion on glueless nameserver cycles).
"""

from __future__ import annotations

import dns.message

from src.resolver import IterativeResolver


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


def test_resolve_returns_direct_answer(tmp_path, monkeypatch):
    resolver = IterativeResolver(cache_path=tmp_path / "cache.json")

    monkeypatch.setattr(
        resolver,
        "_send_query",
        lambda server_ip, qname, rdtype: _answer_response("example.com.", "A", ["1.2.3.4"]),
    )

    result = resolver.resolve("example.com", "A")
    assert result == ["1.2.3.4"]


def test_resolve_follows_referral_with_glue(tmp_path, monkeypatch):
    resolver = IterativeResolver(cache_path=tmp_path / "cache.json")

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
    # 1 query for the referral, 1 for the final answer, plus 1 extra query
    # made by `_ns_info` to resolve the delegated nameserver's own address
    # (already cached from the glue in a real resolver, but not memoised
    # here since glue records aren't fed into the cache in this fake setup).
    assert call_count["n"] == 3


def test_resolve_no_answer_and_no_referral_returns_empty(tmp_path, monkeypatch):
    resolver = IterativeResolver(cache_path=tmp_path / "cache.json")

    monkeypatch.setattr(resolver, "_send_query", lambda server_ip, qname, rdtype: _nodata_response())

    result = resolver.resolve("nonexistent.example", "A")
    assert result == []


def test_resolve_returns_empty_when_all_queries_fail(tmp_path, monkeypatch):
    resolver = IterativeResolver(cache_path=tmp_path / "cache.json")

    monkeypatch.setattr(resolver, "_send_query", lambda server_ip, qname, rdtype: None)

    result = resolver.resolve("example.com", "A")
    assert result == []


def test_resolve_caches_results_across_calls(tmp_path, monkeypatch):
    resolver = IterativeResolver(cache_path=tmp_path / "cache.json")

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


def test_resolve_persists_cache_to_disk(tmp_path, monkeypatch):
    cache_path = tmp_path / "cache.json"
    resolver = IterativeResolver(cache_path=cache_path)

    monkeypatch.setattr(
        resolver,
        "_send_query",
        lambda server_ip, qname, rdtype: _answer_response("example.com.", "A", ["1.2.3.4"]),
    )

    resolver.resolve("example.com", "A")
    resolver.save()

    assert cache_path.exists()

    # A fresh resolver instance should pick up the cached value without any
    # network access at all.
    resolver2 = IterativeResolver(cache_path=cache_path)
    monkeypatch.setattr(
        resolver2,
        "_send_query",
        lambda server_ip, qname, rdtype: (_ for _ in ()).throw(AssertionError("network was hit")),
    )
    assert resolver2.resolve("example.com", "A") == ["1.2.3.4"]


def test_resolve_glueless_nameserver_cycle_does_not_hang(tmp_path, monkeypatch):
    """Regression test for the infinite-recursion bug: a nameserver whose own
    resolution loops back onto itself (no glue) must terminate instead of
    hanging forever."""
    resolver = IterativeResolver(cache_path=tmp_path / "cache.json")

    def fake_send(server_ip, qname, rdtype):
        # Every query, regardless of target, refers to the very same
        # glueless nameserver -- a pathological but real-world-possible
        # configuration.
        return _referral_response("example.com.", ["ns.example.com."], glue=None)

    monkeypatch.setattr(resolver, "_send_query", fake_send)

    # Must return (not hang) and yield no addresses since it never resolves.
    result = resolver.resolve("example.com", "A")
    assert result == []


def test_resolve_full_returns_expected_shape(tmp_path, monkeypatch):
    resolver = IterativeResolver(cache_path=tmp_path / "cache.json")

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

    assert result["domain"] == "example.com"
    assert result["a"] == ["1.2.3.4"]
    assert result["aaaa"] == ["::1"]
    assert "nameserver_ips" in result
    assert "nameservers" in result

