"""Tests for the main.py orchestration script."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import main as main_module
from src.resolver import IterativeResolver


class FakeResolver:
    """Stand-in for IterativeResolver that avoids any network access and
    tracks how many times each domain was actually resolved, to verify the
    shared-cache behaviour across lists.

    `resolve_full` is `async def` to match the real `IterativeResolver`
    (`main.resolve_domains` awaits it via `asyncio.wait_for`), and a
    `stats` attribute is provided since `main._run` unconditionally prints
    `resolver.stats.report()`.
    """

    def __init__(self):
        self.calls = {}
        self.saved = 0
        self.stats = type("Stats", (), {"report": lambda self: "fake stats"})()

    async def resolve_full(self, domain, with_ns_info=True):
        self.calls[domain] = self.calls.get(domain, 0) + 1
        return {
            "hostname": domain,
            "zone": domain,
            "a": ["1.2.3.4"],
            "aaaa": [],
            "nameservers": ["ns1.example.com."],
            "nameserver_ips": [{"name": "ns1.example.com.", "ip": "9.9.9.9"}],
        }

    def save(self):
        self.saved += 1


def test_resolve_domains_preserves_order_and_resolves_each_domain_once():
    resolver = FakeResolver()
    domains = ["a.com", "b.com", "c.com"]

    records = asyncio.run(main_module.resolve_domains(resolver, domains))

    assert [r["hostname"] for r in records] == domains
    assert resolver.calls == {"a.com": 1, "b.com": 1, "c.com": 1}


def test_resolve_domains_handles_duplicate_domains_via_shared_records():
    resolver = FakeResolver()
    domains = ["a.com", "a.com", "b.com"]

    records = asyncio.run(main_module.resolve_domains(resolver, domains))

    # The output should still have one record per (deduplicated) domain,
    # since results are looked up in a dict keyed by domain.
    assert {r["hostname"] for r in records} == {"a.com", "b.com"}


def test_resolve_domains_continues_on_error(monkeypatch):
    resolver = FakeResolver()

    async def flaky_resolve_full(domain, with_ns_info=True):
        if domain == "bad.com":
            raise RuntimeError("boom")
        return {"hostname": domain, "domain": domain, "a": [], "aaaa": [], "nameservers": [], "nameserver_ips": []}

    monkeypatch.setattr(resolver, "resolve_full", flaky_resolve_full)

    records = asyncio.run(main_module.resolve_domains(resolver, ["good.com", "bad.com"]))

    by_domain = {r["hostname"]: r for r in records}
    assert by_domain["good.com"]["a"] == []
    assert "error" in by_domain["bad.com"]


def test_main_writes_one_json_file_per_list(tmp_path, monkeypatch):
    fake_lists = {
        "list-one": ["a.com", "b.com"],
        "list-two": ["c.com"],
    }
    monkeypatch.setattr(main_module, "fetch_all_lists", lambda: fake_lists)
    monkeypatch.setattr(main_module, "RESULTS_DIR", tmp_path / "results")
    monkeypatch.setattr(main_module, "IterativeResolver", lambda: FakeResolver())

    monkeypatch.setattr(sys, "argv", ["main.py", "--date", "2024-01-01"])
    main_module.main()

    out_dir = tmp_path / "results" / "2024-01-01"
    assert (out_dir / "list-one.json").exists()
    assert (out_dir / "list-two.json").exists()

    data = json.loads((out_dir / "list-one.json").read_text())
    assert data["list"] == "list-one"
    assert data["domain_count"] == 2
    assert len(data["records"]) == 2


def test_main_respects_only_filter(tmp_path, monkeypatch):
    fake_lists = {
        "list-one": ["a.com"],
        "list-two": ["b.com"],
    }
    monkeypatch.setattr(main_module, "fetch_all_lists", lambda: fake_lists)
    monkeypatch.setattr(main_module, "RESULTS_DIR", tmp_path / "results")
    monkeypatch.setattr(main_module, "IterativeResolver", lambda: FakeResolver())

    monkeypatch.setattr(sys, "argv", ["main.py", "--date", "2024-01-01", "--only", "list-one"])
    main_module.main()

    out_dir = tmp_path / "results" / "2024-01-01"
    assert (out_dir / "list-one.json").exists()
    assert not (out_dir / "list-two.json").exists()

