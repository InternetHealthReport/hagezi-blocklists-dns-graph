"""Tests for the JSON-backed DiskCache used by the resolver."""

from __future__ import annotations

import time

from src.resolver import DiskCache


def test_set_and_get_roundtrip(tmp_path):
    cache = DiskCache(tmp_path / "cache.json")
    cache.set("example.com.", "A", ["1.2.3.4"])
    assert cache.get("example.com.", "A") == ["1.2.3.4"]


def test_get_missing_key_returns_none(tmp_path):
    cache = DiskCache(tmp_path / "cache.json")
    assert cache.get("missing.example.", "A") is None


def test_key_is_case_and_dot_insensitive(tmp_path):
    cache = DiskCache(tmp_path / "cache.json")
    cache.set("Example.COM.", "a", ["1.2.3.4"])
    assert cache.get("example.com", "A") == ["1.2.3.4"]


def test_expired_entry_is_not_returned(tmp_path):
    cache = DiskCache(tmp_path / "cache.json")
    cache.set("example.com.", "A", ["1.2.3.4"], ttl=60)
    # Manually force expiry in the past.
    key = DiskCache._key("example.com.", "A")
    cache._data[key]["expires"] = time.time() - 1
    assert cache.get("example.com.", "A") is None


def test_save_persists_to_disk_and_reload_recovers_data(tmp_path):
    path = tmp_path / "cache.json"
    cache = DiskCache(path)
    cache.set("example.com.", "AAAA", ["::1"])
    cache.save()

    assert path.exists()

    reloaded = DiskCache(path)
    assert reloaded.get("example.com.", "AAAA") == ["::1"]


def test_corrupted_cache_file_is_ignored(tmp_path):
    path = tmp_path / "cache.json"
    path.write_text("{not valid json")
    cache = DiskCache(path)
    # Should not raise, and should behave like an empty cache.
    assert cache.get("example.com.", "A") is None

