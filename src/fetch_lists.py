"""Fetching of Hagezi domain blocklists.

Hagezi regenerates these lists daily, so a bare list URL ("latest", or a
branch head) is a *moving* target: the exact set of domains we resolved on
a given day becomes impossible to recover a few days later. To keep every
scan reproducible, each run first resolves the moving reference to the
immutable commit it currently points at, downloads the lists pinned to
that commit, and reports the commit hash and date alongside the domains so
the original upstream data can always be found again.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import requests

REQUEST_TIMEOUT = 30

# GitHub repositories the lists are pulled from.
BLOCKLISTS_REPO = "hagezi/dns-blocklists"
NRD_REPO = "hagezi/nrd"

# Pseudo-reference meaning "whatever jsDelivr's `@latest` alias currently
# points at" (i.e. the repository's most recent release tag), as opposed to
# a plain branch name such as "main".
LATEST = "latest"

# Resolves jsDelivr's `@latest` alias to the concrete tag behind it, so we
# stay consistent with the exact revision jsDelivr would have served us.
JSDELIVR_RESOLVE_URL = (
    "https://data.jsdelivr.com/v1/packages/gh/{repo}/resolved?specifier={specifier}"
)
# Turns any reference (tag, branch, "HEAD") into the commit it points at.
GITHUB_COMMIT_URL = "https://api.github.com/repos/{repo}/commits/{ref}"

# Content URL templates, per CDN. Both accept a full commit hash in place of
# the moving reference, which is what lets us pin a download to an exact
# upstream revision.
CONTENT_URL_TEMPLATES: Dict[str, str] = {
    "jsdelivr": "https://cdn.jsdelivr.net/gh/{repo}@{ref}/{path}",
    "raw": "https://raw.githubusercontent.com/{repo}/{ref}/{path}",
}


@dataclass(frozen=True)
class Commit:
    """An upstream revision: its hash and when it was committed.

    `date` is the ISO 8601 timestamp reported by GitHub (e.g.
    "2024-05-01T03:00:00Z"), or `None` if the API response didn't carry
    one. It tells us how fresh the blocklist data was at scan time, which
    the scan date alone doesn't: Hagezi publishes several commits a day,
    and a scan may run hours after the revision it pinned.
    """

    hash: str
    date: Optional[str] = None


@dataclass(frozen=True)
class BlocklistSource:
    """Where a blocklist comes from, independently of any given revision."""

    repo: str
    path: str
    ref: str = LATEST
    cdn: str = "jsdelivr"

    def url_at(self, ref: str) -> str:
        """Return the download URL for this list at `ref` (a commit hash,
        tag or branch name)."""
        return CONTENT_URL_TEMPLATES[self.cdn].format(
            repo=self.repo, ref=ref, path=self.path
        )


@dataclass(frozen=True)
class Blocklist:
    """A downloaded blocklist, plus the exact upstream revision it came from.

    `commit` is the Hagezi commit the domains were downloaded from, or
    `None` when it could not be resolved (e.g. the GitHub API was
    unreachable or rate-limited), in which case the list was downloaded
    from the moving `ref` instead.
    """

    name: str
    domains: List[str]
    repo: str
    ref: str
    commit: Optional[Commit]
    url: str


# Mapping of list name -> source.
BLOCKLISTS: Dict[str, BlocklistSource] = {
    "fake": BlocklistSource(BLOCKLISTS_REPO, "wildcard/fake-onlydomains.txt"),
    "popup-ads": BlocklistSource(BLOCKLISTS_REPO, "wildcard/popupads-onlydomains.txt"),
    # "threat": BlocklistSource(BLOCKLISTS_REPO, "wildcard/tif-onlydomains.txt"),
    "threat-med": BlocklistSource(BLOCKLISTS_REPO, "wildcard/tif.medium-onlydomains.txt"),
    # "nrd": BlocklistSource(NRD_REPO, "domains/nrd7.txt", ref="main", cdn="raw"),
    "nrd-dga": BlocklistSource(NRD_REPO, "domains/dga7.txt", ref="main", cdn="raw"),
    "encrypted-dns-resolver": BlocklistSource(BLOCKLISTS_REPO, "wildcard/doh-onlydomains.txt"),
    "dynamic-dns": BlocklistSource(BLOCKLISTS_REPO, "wildcard/dyndns-onlydomains.txt"),
    "url-shortener": BlocklistSource(BLOCKLISTS_REPO, "wildcard/urlshortener-onlydomains.txt"),
    "piracy": BlocklistSource(BLOCKLISTS_REPO, "wildcard/anti.piracy-onlydomains.txt"),
    "gambling": BlocklistSource(BLOCKLISTS_REPO, "wildcard/gambling-onlydomains.txt"),
    "social-networks": BlocklistSource(BLOCKLISTS_REPO, "wildcard/social-onlydomains.txt"),
    "nsfw": BlocklistSource(BLOCKLISTS_REPO, "wildcard/nsfw-onlydomains.txt"),
}


def fetch_domain_list(url: str) -> List[str]:
    """Download a plain-text list of domains (one per line)."""
    response = requests.get(url, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    domains = []
    for line in response.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        domains.append(line.lower())
    return domains


def _resolve_jsdelivr_version(repo: str, specifier: str = LATEST) -> Optional[str]:
    """Return the concrete tag jsDelivr's `@{specifier}` alias points at."""
    url = JSDELIVR_RESOLVE_URL.format(repo=repo, specifier=specifier)
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return response.json().get("version")
    except (requests.RequestException, ValueError):
        return None


def _resolve_github_commit(repo: str, ref: str) -> Optional[Commit]:
    """Return the commit (hash + date) `ref` points at.

    `ref` may be a tag, a branch name or "HEAD".
    """
    url = GITHUB_COMMIT_URL.format(repo=repo, ref=ref)
    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"Accept": "application/vnd.github+json"},
        )
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, ValueError):
        return None

    commit_hash = payload.get("sha")
    if not commit_hash:
        return None
    # Prefer the committer date over the author date: for generated lists
    # they are usually identical, but the committer date is the one that
    # reflects when the revision actually landed in the repository.
    commit = payload.get("commit") or {}
    date = (commit.get("committer") or {}).get("date") or (
        commit.get("author") or {}
    ).get("date")
    return Commit(commit_hash, date)


def resolve_commit(source: BlocklistSource) -> Optional[Commit]:
    """Resolve `source`'s moving reference to the commit it currently points
    at, or `None` if it cannot be determined.

    Resolution is best-effort on purpose: the upstream APIs used here are
    anonymous (and therefore rate-limited, which is easy to hit from shared
    CI runners), and failing to pin a revision should only degrade the
    metadata we record rather than abort a whole scan.
    """
    ref = source.ref
    if ref == LATEST:
        # `@latest` is a jsDelivr-side alias, not something GitHub knows
        # about: ask jsDelivr which tag it currently resolves to, and fall
        # back to the repository's default branch head if that fails.
        ref = _resolve_jsdelivr_version(source.repo) or "HEAD"
    return _resolve_github_commit(source.repo, ref)


def fetch_blocklist(
    name: str, source: BlocklistSource, commit: Optional[Commit] = None
) -> Blocklist:
    """Download a single blocklist, pinned to `commit` when it is known."""
    if commit is not None:
        url = source.url_at(commit.hash)
        try:
            domains = fetch_domain_list(url)
        except requests.RequestException:
            # The pinned revision isn't available from the CDN (yet): retry
            # against the moving reference below, and forget the commit
            # rather than recording a revision that doesn't match the data
            # we ended up downloading.
            pass
        else:
            return Blocklist(name, domains, source.repo, source.ref, commit, url)

    url = source.url_at(source.ref)
    return Blocklist(name, fetch_domain_list(url), source.repo, source.ref, None, url)


def fetch_all_lists() -> Dict[str, Blocklist]:
    """Download every configured blocklist. Returns {name: Blocklist}.

    Each source repository's revision is resolved only once per run, so all
    lists coming from the same repository are guaranteed to be downloaded
    from the very same commit -- even if Hagezi publishes an update midway
    through a long scan.
    """
    commits: Dict[Tuple[str, str], Optional[Commit]] = {}
    result: Dict[str, Blocklist] = {}
    for name, source in BLOCKLISTS.items():
        key = (source.repo, source.ref)
        if key not in commits:
            commits[key] = resolve_commit(source)
        result[name] = fetch_blocklist(name, source, commits[key])
    return result

