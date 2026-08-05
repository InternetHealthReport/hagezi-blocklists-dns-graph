"""Fetch Hagezi blocklists, resolve every domain (iteratively, with caching),
and write one JSON result file per list under results/<date>/<list>.json.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import date, datetime, timezone
from pathlib import Path

from src.fetch_lists import fetch_all_lists
from src.resolver import IterativeResolver

try:
    import resource
except ImportError:  # pragma: no cover - resource is POSIX-only
    resource = None

RESULTS_DIR = Path("results")

# Maximum number of domains being resolved concurrently. Since resolution is
# now fully asyncio-based (no blocking sockets, no per-domain OS thread),
# this can safely be much higher than a thread pool's practical size -- the
# real limits are the remote name servers' tolerance for concurrent queries
# and local file-descriptor/ephemeral-port limits, not thread overhead.
#
# NOTE: each in-flight domain resolution can hold open several UDP sockets
# at once (racing up to MAX_RACE servers, for NS + A + AAAA queries), so the
# number of file descriptors in use at any given time can be several times
# MAX_CONCURRENCY. This must stay comfortably under the process's open-file
# limit (see `_raise_fd_limit` below), or queries will silently fail with
# OSError ("too many open files") and get cached as negative results.
MAX_CONCURRENCY = 4096

# Rough upper bound on file descriptors a single in-flight resolution can
# use at once (MAX_RACE candidate sockets x up to 3 concurrent query types).
FDS_PER_DOMAIN = 10


def _raise_fd_limit(min_needed: int) -> None:
    """Raise the process's soft open-file limit as high as the hard limit
    allows, so MAX_CONCURRENCY doesn't silently exceed it.

    On most Linux systems the default soft limit (often 1024) is far lower
    than what's needed to have thousands of domains resolving concurrently,
    each with several open UDP sockets. The hard limit is usually much
    higher, so simply raising the soft limit is normally sufficient and
    doesn't require any privileges.
    """
    if resource is None:
        return
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    target = min(min_needed, hard if hard != resource.RLIM_INFINITY else min_needed)
    if soft < target:
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
        except (ValueError, OSError) as exc:
            print(
                f"Warning: could not raise open-file limit to {target} "
                f"(current soft={soft}, hard={hard}): {exc}. "
                "Consider lowering MAX_CONCURRENCY or raising the limit manually.",
                file=sys.stderr,
            )

# How often the progress bar is redrawn, in completed domains. Rendering on
# every single completion means a formatted, flushed stderr write per domain
# from a loop fed by thousands of worker threads, which is pure overhead.
PROGRESS_EVERY = 100


def _print_progress(prefix: str, done: int, total: int, bar_width: int = 40) -> None:
    """Render a simple in-place progress bar on stderr."""
    fraction = done / total if total else 1.0
    filled = int(bar_width * fraction)
    bar = "#" * filled + "-" * (bar_width - filled)
    print(
        f"\r{prefix} [{bar}] {done}/{total} ({fraction * 100:5.1f}%)",
        end="" if done < total else "\n",
        file=sys.stderr,
        flush=True,
    )


async def resolve_domains(
    resolver: IterativeResolver,
    domains: list[str],
    list_name: str = "",
    with_ns_info: bool = False,
) -> list[dict]:
    """Resolve a list of domains concurrently on the asyncio event loop,
    bounded by a semaphore, while going through the resolver's shared cache
    (so duplicate domains, even across lists, are only ever queried once).

    `with_ns_info` is forwarded to `resolve_full`: skipping nameserver-IP
    resolution roughly halves the number of DNS round trips per domain,
    which matters a lot at million-domain scale.
    """
    records: dict[str, dict] = {}
    total = len(domains)
    prefix = f"  {list_name}" if list_name else "  Resolving"
    semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
    done = 0

    async def _job(domain: str) -> None:
        nonlocal done
        async with semaphore:
            try:
                result = await resolver.resolve_full(domain, with_ns_info=with_ns_info)
            except Exception as exc:  # keep going even if one domain fails
                result = {"hostname": domain, "error": str(exc)}
        records[domain] = result
        done += 1
        if done % PROGRESS_EVERY == 0 or done == total:
            _print_progress(prefix, done, total)

    _print_progress(prefix, done, total)
    await asyncio.gather(*(_job(domain) for domain in domains))

    return [records[d] for d in domains if d in records]


async def _run(args: argparse.Namespace) -> None:
    output_dir = RESULTS_DIR / args.date
    output_dir.mkdir(parents=True, exist_ok=True)

    print("Fetching blocklists...", file=sys.stderr)
    all_lists = fetch_all_lists()
    if args.only:
        all_lists = {k: v for k, v in all_lists.items() if k in args.only}

    resolver = IterativeResolver()

    for name, domains in all_lists.items():
        print(f"Resolving {len(domains)} domains for list '{name}'...", file=sys.stderr)
        records = await resolve_domains(resolver, domains, list_name=name, with_ns_info=True)

        output = {
            "list": name,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "domain_count": len(domains),
            "records": records,
        }
        out_path = output_dir / f"{name}.json"
        out_path.write_text(json.dumps(output, indent=2))
        print(f"Wrote {out_path}", file=sys.stderr)

    print("Done.", file=sys.stderr)


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
    _raise_fd_limit(MAX_CONCURRENCY * FDS_PER_DOMAIN)
    asyncio.run(_run(args))


if __name__ == "__main__":
    main()
