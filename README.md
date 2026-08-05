# hagezi-blocklists-intel

Fetches the [Hagezi](https://github.com/hagezi/dns-blocklists) DNS
blocklists, resolves every listed domain, and stores the results
(A/AAAA records, authoritative name servers and their IPs) as JSON,
one file per list, per day.

## How it works

- `src/fetch_lists.py` downloads the plain-text domain lists (fake domains,
  pop-up ads, threats, newly registered domains, NRD+DGA, DoH resolvers,
  dynamic DNS, URL shorteners, piracy, gambling, social networks, NSFW).
- `src/resolver.py` implements a small **iterative** DNS resolver: it
  starts at the root servers and follows NS referrals down to the
  authoritative servers itself, instead of hammering a single recursive
  resolver. Every lookup (A/AAAA/NS, including nameserver hostname
  resolution) is cached in memory, along with the zone cuts discovered
  along the way, so a domain that appears in several lists is only ever
  queried once and lookups sharing a TLD skip the root servers entirely.
- `main.py` orchestrates fetching + resolving (with a thread pool, since
  the DNS cache is shared and thread-safe) and writes
  `results/<date>/<list-name>.json` files, e.g. `results/2024-05-01/nrd.json`.

## Usage

```bash
uv sync
uv run main.py                      # resolve all lists for today
uv run main.py --date 2024-05-01    # use a specific date for the output dir
uv run main.py --only nrd nsfw      # only process specific lists
```

## Output format

Each `results/<date>/<list>.json` file looks like:

```json
{
  "list": "nsfw",
  "generated_at": "2024-05-01T03:00:00+00:00",
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

## Automation

A GitHub Actions workflow (`.github/workflows/daily.yml`) runs the whole
pipeline every day at 03:00 UTC and commits the new `results/<date>/`
directory back to the repository, keeping every day's results separate.

