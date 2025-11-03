from __future__ import annotations
import argparse
from typing import Dict, Any

from config.sources import SOURCES
from helpers.state import load_state, save_state
from helpers.parse_source import process_source
from helpers import log

KIND_ALL = "all"

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Process JSON CIDR sources and patch SafeLine groups."
    )
    p.add_argument(
        "--only",
        nargs="*",
        help="Process only these source names (space-separated). Example: --only googlebot bingbot"
    )
    p.add_argument(
        "--kind",
        default=KIND_ALL,
        choices=[KIND_ALL, "json-cidrs", "whois-radb", "abuseipdb", "txt-cidrs"],
        help="Limit processing to a specific source kind."
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not push to SafeLine; only show what would be done."
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    state: Dict[str, Any] = load_state()

    if args.dry_run:
        log.info("Dry-run enabled: no changes will be pushed.")

    selected = set(args.only) if args.only else None
    processed = 0


    for name, cfg in SOURCES.items():
        if selected and name not in selected:
            continue
        if not cfg.get("enabled", False):
            continue
        if args.kind != KIND_ALL and cfg.get("kind") != args.kind:
            continue

        log.info("=== [%s] kind=%s ===", name, cfg.get("kind"))
        try:
            process_source(name, cfg, state)
            processed += 1
        except Exception as e:
            log.error("%s: %s", name, e)

    save_state(state)
    if processed == 0:
        log.warning("No sources matched your filters. Check 'enabled', --only, or --kind.")
    else:
        log.info("Sources processed: %s", processed)


if __name__ == "__main__":
    main()