"""Tests for src.fetch_lists."""

from __future__ import annotations

import responses

from src.fetch_lists import BLOCKLISTS, fetch_all_lists, fetch_domain_list


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

    try:
        fetch_domain_list(url)
    except Exception:
        pass
    else:
        raise AssertionError("Expected an exception for a 404 response")


@responses.activate
def test_fetch_all_lists_downloads_every_configured_list():
    for url in BLOCKLISTS.values():
        responses.add(responses.GET, url, body="domain-a.com\ndomain-b.com\n", status=200)

    result = fetch_all_lists()

    assert set(result.keys()) == set(BLOCKLISTS.keys())
    for domains in result.values():
        assert domains == ["domain-a.com", "domain-b.com"]

