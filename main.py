"""Fetch Hagezi blocklists, resolve every domain (iteratively, with caching),
and write one JSON result file per list under results/<date>/<list>.json.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from concurrent.futures import ProcessPoolExecutor
from datetime import date, datetime, timezone
from pathlib import Path

from src.fetch_lists import fetch_all_lists
from src.resolver import CLOUDFLARE_DNS, IterativeResolver

try:
    import resource
except ImportError:  # pragma: no cover - resource is POSIX-only
    resource = None

# Use uvloop's C-based event loop instead of the stdlib asyncio one when it
# is available: for a workload that is almost entirely "schedule tens of
# thousands of tiny coroutines and wake them up on socket I/O" (exactly what
# this resolver does), uvloop's scheduling/callback overhead is measurably
# lower than the pure-Python default loop, which directly reduces CPU time
# spent outside of actual DNS I/O. This is a no-op (falls back silently) on
# platforms where uvloop isn't installed/available (e.g. Windows).
try:
    import uvloop

    uvloop.install()
except ImportError:  # pragma: no cover - optional dependency
    uvloop = None

RESULTS_DIR = Path("results")

# Maximum number of domains being resolved concurrently *within a single
# worker process*. Since resolution is fully asyncio-based (no blocking
# sockets, no per-domain OS thread), this can safely be much higher than a
# thread pool's practical size -- the real limits are the remote name
# servers' tolerance for concurrent queries and local file-descriptor/
# ephemeral-port limits, not thread overhead.
#
# NOTE: each in-flight domain resolution can hold open several UDP sockets
# at once (racing up to MAX_RACE servers, for NS + A + AAAA queries), so the
# number of file descriptors in use at any given time can be several times
# MAX_CONCURRENCY. This must stay comfortably under the process's open-file
# limit (see `_raise_fd_limit` below), or queries will silently fail with
# OSError ("too many open files") and get cached as negative results.
MAX_CONCURRENCY = 1

# Rough upper bound on file descriptors a single in-flight resolution can
# use at once (MAX_RACE candidate sockets x up to 3 concurrent query types).
FDS_PER_DOMAIN = 10

# Per-domain resolution timeout in seconds. Guards against hangs in resolver.
PER_DOMAIN_TIMEOUT = 60

# Default number of worker *processes* used to resolve a single list.
#
# asyncio (and therefore the whole resolver) is single-threaded: no matter
# how many thousands of domains are "concurrently" in flight, all of the
# actual Python bytecode -- DNS wire-format parsing/building, cache
# bookkeeping, etc. -- runs on one CPU core, serialized by the GIL. Once DNS
# I/O is no longer the bottleneck (e.g. most answers come from nearby/fast
# resolvers or from the zone cache), that per-query CPU work becomes the
# limiting factor, and the only way to use more than one core for it is
# real OS processes. Each worker process gets its own event loop and its
# own `IterativeResolver` (so its own cache/zone-cache), and a list's
# domains are simply partitioned across them.
DEFAULT_WORKERS = os.cpu_count() or 1


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
PROGRESS_EVERY = 1000


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
                # Guard each individual domain resolve with a timeout so a bug
                # or unexpected hang in the resolver doesn't stall the whole
                # worker pool forever.
                try:
                    result = await asyncio.wait_for(
                        resolver.resolve_full(domain, with_ns_info=with_ns_info),
                        timeout=PER_DOMAIN_TIMEOUT,
                    )
                except asyncio.TimeoutError:
                    # `resolver.resolve_full` was cancelled by `wait_for`
                    # before it could reach its own `finally` block (see
                    # `ResolverStats.record_domain`), so this timeout would
                    # otherwise go completely unaccounted for in the
                    # resolver's stats. Record it here instead.
                    resolver.stats.record_domain(PER_DOMAIN_TIMEOUT, timed_out=True)
                    result = {"hostname": domain, "error": f"timeout after {PER_DOMAIN_TIMEOUT}s"}
            except Exception as exc:  # keep going even if one domain fails
                result = {"hostname": domain, "error": str(exc)}
        records[domain] = result
        done += 1
        if done % PROGRESS_EVERY == 0 or done == total:
            _print_progress(prefix, done, total)

    _print_progress(prefix, done, total)
    await asyncio.gather(*(_job(domain) for domain in domains))

    return [records[d] for d in domains if d in records]


def _chunk(items: list[str], n: int) -> list[list[str]]:
    """Split `items` into at most `n` contiguous, roughly equal chunks,
    dropping any empty chunks (e.g. when there are fewer domains than
    workers)."""
    if n <= 1 or len(items) <= 1:
        return [items] if items else []
    size = -(-len(items) // n)  # ceil division
    chunks = [items[i : i + size] for i in range(0, len(items), size)]
    return [c for c in chunks if c]


def _resolve_chunk_in_process(
    domains: list[str], list_name: str, with_ns_info: bool, recursive_server: str | None = None
) -> tuple[list[dict], str]:
    """Entry point run inside a worker *process* (via `ProcessPoolExecutor`):
    builds its own event loop and its own `IterativeResolver` (own cache/
    zone-cache) and resolves its share of `domains`.

    This -- and not just more asyncio concurrency -- is what lets the
    resolver actually use more than one CPU core: asyncio is single-threaded,
    so once queries are I/O-bound rather than CPU-bound, no amount of extra
    concurrency within one process buys more throughput once a single core
    is saturated with DNS-message parsing/building and cache bookkeeping.

    Returns `(records, stats_report)` so the parent process can merge
    results back in original order and print each worker's stats.
    """
    # Each process needs its own uvloop install (module-level state doesn't
    # cross the fork/spawn boundary in a way we can rely on for spawn-start
    # workers), so re-apply it here too.
    if uvloop is not None:
        uvloop.install()

    resolver = IterativeResolver(recursive_server=recursive_server)
    records = asyncio.run(
        resolve_domains(resolver, domains, list_name=list_name, with_ns_info=with_ns_info)
    )
    return records, resolver.stats.report()


async def _resolve_list_multiprocess(
    domains: list[str],
    list_name: str,
    with_ns_info: bool,
    workers: int,
    recursive_server: str | None = None,
) -> list[dict]:
    """Partition `domains` across `workers` processes and resolve each
    partition in parallel, then reassemble the results in original order.

    Falls back to plain in-process (single-core) resolution when there
    are too few domains, or only one worker, to make process-spawning
    overhead worthwhile.
    """
    chunks = _chunk(domains, workers)
    if len(chunks) <= 1:
        resolver = IterativeResolver(recursive_server=recursive_server)
        records = await resolve_domains(
            resolver, domains, list_name=list_name, with_ns_info=with_ns_info
        )
        print(resolver.stats.report(), file=sys.stderr)
        return records

    print(
        f"  {list_name}: splitting {len(domains)} domains across {len(chunks)} worker processes",
        file=sys.stderr,
    )
    loop = asyncio.get_event_loop()
    with ProcessPoolExecutor(max_workers=len(chunks)) as pool:
        futures = [
            loop.run_in_executor(
                pool,
                _resolve_chunk_in_process,
                chunk,
                f"{list_name}[{i}]",
                with_ns_info,
                recursive_server,
            )
            for i, chunk in enumerate(chunks)
        ]
        chunk_results = await asyncio.gather(*futures)

    records: list[dict] = []
    for i, (chunk_records, stats_report) in enumerate(chunk_results):
        records.extend(chunk_records)
        print(f"  {list_name}[{i}] done:\n{stats_report}", file=sys.stderr)
    return records


async def _run(args: argparse.Namespace) -> None:
    output_dir = RESULTS_DIR / args.date
    output_dir.mkdir(parents=True, exist_ok=True)

    print("Fetching blocklists...", file=sys.stderr)
    all_lists = fetch_all_lists()
    if args.only:
        all_lists = {k: v for k, v in all_lists.items() if k in args.only}

    for name, domains in all_lists.items():
        print(f"Resolving {len(domains)} domains for list '{name}'...", file=sys.stderr)
        records = await _resolve_list_multiprocess(
            domains,
            name,
            with_ns_info=True,
            workers=args.workers,
            recursive_server=args.recursive_resolver,
        )

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
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help=(
            "Number of worker processes used to resolve each list's domains "
            f"in parallel (default: {DEFAULT_WORKERS}, i.e. one per CPU core). "
            "Set to 1 to disable multiprocessing."
        ),
    )
    parser.add_argument(
        "--recursive-resolver",
        dest="recursive_resolver",
        nargs="?",
        const=CLOUDFLARE_DNS,
        default=None,
        metavar="IP",
        help=(
            "Bypass our own iterative (root -> TLD -> authoritative) "
            "resolution and instead query this recursive resolver IP "
            "directly for every lookup (e.g. useful in CI environments "
            "where iterative queries get rate-limited by authoritative "
            f"servers). If given without a value, defaults to {CLOUDFLARE_DNS} "
            "(Cloudflare). Disabled (own iterative resolution) by default."
        ),
    )
    args = parser.parse_args()
    _raise_fd_limit(MAX_CONCURRENCY * FDS_PER_DOMAIN)
    asyncio.run(_run(args))


if __name__ == "__main__":
    main()
