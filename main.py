"""Fetch Hagezi blocklists, resolve every domain (iteratively, with caching),
and write one JSON result file per list under results/<date>/<list>.json.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import sys
from datetime import date, datetime, timezone
from pathlib import Path

from src.fetch_lists import fetch_all_lists
from src.resolver import IterativeResolver

RESULTS_DIR = Path("results")
CACHE_PATH = Path(".cache") / "dns_cache.json"
MAX_WORKERS = 16


def resolve_domains(resolver: IterativeResolver, domains: list[str]) -> list[dict]:
    """Resolve a list of domains, using a thread pool for concurrency while
    still going through the resolver's shared cache (so duplicate domains,
    even across lists, are only ever queried once)."""
    records: dict[str, dict] = {}

    def _job(domain: str):
        try:
            return domain, resolver.resolve_full(domain)
        except Exception as exc:  # keep going even if one domain fails
            return domain, {"domain": domain, "error": str(exc)}

    with cf.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        for domain, result in executor.map(_job, domains):
            records[domain] = result

    return [records[d] for d in domains if d in records]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--date",
        default=date.today().isoformat(),
        help="Date (YYYY-MM-DD) used for the output directory, defaults to today.",
    )
    parser.add_argument(
        "--only",
        nargs="*",
        default=None,
        help="Only process these list names (default: all).",
    )
    args = parser.parse_args()

    output_dir = RESULTS_DIR / args.date
    output_dir.mkdir(parents=True, exist_ok=True)

    print("Fetching blocklists...", file=sys.stderr)
    all_lists = fetch_all_lists()
    if args.only:
        all_lists = {k: v for k, v in all_lists.items() if k in args.only}

    resolver = IterativeResolver(cache_path=CACHE_PATH)

    for name, domains in all_lists.items():
        print(f"Resolving {len(domains)} domains for list '{name}'...", file=sys.stderr)
        records = resolve_domains(resolver, domains)
        resolver.save()  # persist cache incrementally

        output = {
            "list": name,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "domain_count": len(domains),
            "records": records,
        }
        out_path = output_dir / f"{name}.json"
        out_path.write_text(json.dumps(output, indent=2))
        print(f"Wrote {out_path}", file=sys.stderr)

    resolver.save()
    print("Done.", file=sys.stderr)


if __name__ == "__main__":
    main()
