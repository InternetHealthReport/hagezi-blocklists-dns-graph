"""Tests for src.fetch_lists."""

from __future__ import annotations

import re

import pytest
import requests
import responses

from src.fetch_lists import (
    BLOCKLISTS,
    GITHUB_COMMIT_URL,
    JSDELIVR_RESOLVE_URL,
    LATEST,
    Blocklist,
    BlocklistSource,
    Commit,
    fetch_all_lists,
    fetch_blocklist,
    fetch_domain_list,
    resolve_commit,
)

TAG = "37522026.258.33217"
COMMIT_HASH = "c30a9937e79f18bb31dcf4d45ac4988c3ddc8e7a"
COMMIT_DATE = "2024-05-01T03:00:00Z"
COMMIT = Commit(COMMIT_HASH, COMMIT_DATE)

GITHUB_COMMIT_ANY = re.compile(r"https://api\.github\.com/repos/[^?]+/commits/.+")
CONTENT_ANY = re.compile(
    r"https://(cdn\.jsdelivr\.net|raw\.githubusercontent\.com)/.+"
)


def _mock_revision_apis(version: str = TAG, commit: Commit = COMMIT) -> None:
    """Register the two endpoints used to pin a run to an exact revision."""
    for repo in {source.repo for source in BLOCKLISTS.values()}:
        responses.add(
            responses.GET,
            JSDELIVR_RESOLVE_URL.format(repo=repo, specifier=LATEST),
            json={"version": version},
            status=200,
        )
    responses.add(
        responses.GET,
        GITHUB_COMMIT_ANY,
        json={
            "sha": commit.hash,
            "commit": {"committer": {"date": commit.date}},
        },
        status=200,
    )


@responses.activate
def test_fetch_domain_list_strips_blank_lines_and_comments():
    url = "https://example.org/list.txt"
    responses.add(
        responses.GET,
        url,
        body="# comment\nExample.COM\n\n  domain2.net  \n#another comment\ndomain3.org\n",
        status=200,
    )

    domains = fetch_domain_list(url)

    assert domains == ["example.com", "domain2.net", "domain3.org"]


@responses.activate
def test_fetch_domain_list_raises_on_http_error():
    url = "https://example.org/missing.txt"
    responses.add(responses.GET, url, status=404)

    with pytest.raises(requests.HTTPError):
        fetch_domain_list(url)


@responses.activate
def test_resolve_commit_resolves_the_latest_alias_then_the_commit():
    source = BLOCKLISTS["fake"]
    responses.add(
        responses.GET,
        JSDELIVR_RESOLVE_URL.format(repo=source.repo, specifier=LATEST),
        json={"version": TAG},
        status=200,
    )
    responses.add(
        responses.GET,
        GITHUB_COMMIT_URL.format(repo=source.repo, ref=TAG),
        json={"sha": COMMIT_HASH, "commit": {"committer": {"date": COMMIT_DATE}}},
        status=200,
    )

    assert resolve_commit(source) == COMMIT


@responses.activate
def test_resolve_commit_uses_the_branch_name_directly_for_branch_refs():
    source = BlocklistSource("hagezi/nrd", "domains/dga7.txt", ref="main", cdn="raw")
    responses.add(
        responses.GET,
        GITHUB_COMMIT_URL.format(repo=source.repo, ref="main"),
        json={"sha": COMMIT_HASH, "commit": {"committer": {"date": COMMIT_DATE}}},
        status=200,
    )

    assert resolve_commit(source) == COMMIT


@responses.activate
def test_resolve_commit_returns_none_when_the_apis_are_unavailable():
    """A rate-limited/unreachable API must degrade the recorded metadata,
    not abort the scan."""
    source = BLOCKLISTS["fake"]
    responses.add(
        responses.GET,
        JSDELIVR_RESOLVE_URL.format(repo=source.repo, specifier=LATEST),
        status=429,
    )
    responses.add(responses.GET, GITHUB_COMMIT_ANY, status=403)

    assert resolve_commit(source) is None


@responses.activate
def test_fetch_blocklist_pins_the_download_to_the_commit():
    source = BLOCKLISTS["fake"]
    responses.add(
        responses.GET, source.url_at(COMMIT_HASH), body="a.com\nb.com\n", status=200
    )

    blocklist = fetch_blocklist("fake", source, COMMIT)

    assert blocklist.domains == ["a.com", "b.com"]
    assert blocklist.commit == COMMIT
    assert COMMIT_HASH in blocklist.url


@responses.activate
def test_fetch_blocklist_falls_back_to_the_moving_ref_and_drops_the_commit():
    """If the pinned revision isn't served (yet), we must not record a
    commit that doesn't match the data we actually downloaded."""
    source = BLOCKLISTS["fake"]
    responses.add(responses.GET, source.url_at(COMMIT_HASH), status=404)
    responses.add(responses.GET, source.url_at(LATEST), body="a.com\n", status=200)

    blocklist = fetch_blocklist("fake", source, COMMIT)

    assert blocklist.domains == ["a.com"]
    assert blocklist.commit is None
    assert blocklist.url == source.url_at(LATEST)


@responses.activate
def test_fetch_blocklist_without_a_commit_uses_the_moving_ref():
    source = BLOCKLISTS["fake"]
    responses.add(responses.GET, source.url_at(LATEST), body="a.com\n", status=200)

    blocklist = fetch_blocklist("fake", source, None)

    assert blocklist.commit is None
    assert blocklist.url == source.url_at(LATEST)


@responses.activate
def test_fetch_all_lists_downloads_every_configured_list_pinned_to_a_commit():
    _mock_revision_apis()
    responses.add(
        responses.GET, CONTENT_ANY, body="domain-a.com\ndomain-b.com\n", status=200
    )

    result = fetch_all_lists()

    assert set(result.keys()) == set(BLOCKLISTS.keys())
    for name, blocklist in result.items():
        assert isinstance(blocklist, Blocklist)
        assert blocklist.domains == ["domain-a.com", "domain-b.com"]
        # Every list records the exact revision it came from, and was
        # downloaded from that very revision.
        assert blocklist.commit == COMMIT
        assert COMMIT_HASH in blocklist.url, name


@responses.activate
def test_fetch_all_lists_resolves_each_repository_revision_only_once():
    """All lists from one repo must share a single commit, so a scan that
    straddles an upstream update can't mix revisions."""
    _mock_revision_apis()
    responses.add(responses.GET, CONTENT_ANY, body="domain-a.com\n", status=200)

    fetch_all_lists()

    commit_lookups = [
        call.request.url
        for call in responses.calls
        if "api.github.com" in call.request.url
    ]
    repos = {source.repo for source in BLOCKLISTS.values()}
    assert len(commit_lookups) == len(repos)

