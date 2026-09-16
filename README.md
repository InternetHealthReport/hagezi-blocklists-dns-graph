# hagezi-blocklists-dns-graph

Fetches the [Hagezi](https://github.com/hagezi/dns-blocklists) DNS
blocklists, resolves every listed domain, and stores the results
(A/AAAA records, authoritative name servers and their IPs) as JSON,
one file per list, per scan. Currently set to fetch data once per week.

## How it works

- `src/fetch_lists.py` downloads the plain-text domain lists (fake domains,
  pop-up ads, threats, newly registered domains, NRD+DGA, DoH resolvers,
  dynamic DNS, URL shorteners, piracy, gambling, social networks, NSFW).
  Hagezi rebuilds those lists daily, so before downloading anything each
  run resolves the moving reference (jsDelivr's `@latest` alias, or a
  branch head) to the **exact upstream commit** it currently points at,
  downloads every list pinned to that commit, and records the commit hash
  and date in the output. That is what makes a scan reproducible: the
  original input data can always be found back in the Hagezi repository.
  A repository's revision is resolved only once per run, so lists coming
  from the same repository can never end up mixing two revisions.
- `src/resolver.py` implements a small **iterative** DNS resolver: it
  starts at the root servers and follows NS referrals down to the
  authoritative servers itself, instead of hammering a single recursive
  resolver. Every lookup (A/AAAA/NS, including nameserver hostname
  resolution) is cached in memory, along with the zone cuts discovered
  along the way, so a domain that appears in several lists is only ever
  queried once and lookups sharing a TLD skip the root servers entirely.
- `main.py` orchestrates fetching + resolving (across worker processes,
  each with its own event loop and cache) and writes
  `results/<date>/<list-name>.json.gz` files, e.g.
  `results/2024-05-01/nrd.json.gz`.

## Usage

```bash
uv sync
uv run main.py                      # resolve all lists for today
uv run main.py --date 2024-05-01    # use a specific date for the output dir
uv run main.py --only nrd nsfw      # only process specific lists
```

## Output format

Each `results/<date>/<list>.json.gz` file contains:

```json
{
  "list": "nsfw",
  "generated_at": "2024-05-01T03:00:00+00:00",
  "source": {
    "repo": "hagezi/dns-blocklists",
    "ref": "latest",
    "commit": "c30a9937e79f18bb31dcf4d45ac4988c3ddc8e7a",
    "commit_date": "2024-05-01T01:12:33Z",
    "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@c30a9937e79f18bb31dcf4d45ac4988c3ddc8e7a/wildcard/nsfw-onlydomains.txt"
  },
  "domain_count": 12345,
  "records": [
    {
      "hostname": "example.com",
      "zone": "example.com",
      "a": ["93.184.216.34"],
      "aaaa": ["2606:2800:220:1:248:1893:25c8:1946"],
      "nameservers": ["a.iana-servers.net", "b.iana-servers.net"],
      "nameserver_ips": [
        {"name": "a.iana-servers.net", "ip": "199.43.135.53"},
        {"name": "b.iana-servers.net", "ip": "199.43.133.53"}
      ]
    }
  ]
}
```

`source` identifies the exact upstream data a scan was built from:
`commit` is the Hagezi commit hash the domains were downloaded from,
`commit_date` is when that revision was published upstream, and `url` is
the pinned download URL (also browsable as
`https://github.com/<repo>/tree/<commit>`). Both `commit` and
`commit_date` are `null` when the revision could not be resolved (e.g. the
GitHub API was rate-limited), in which case `url` points at the moving
reference instead.

## Automation

We are collecting data once a week (sunday at 10:00 UTC) and push new results here.

