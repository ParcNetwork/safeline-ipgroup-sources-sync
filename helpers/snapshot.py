from __future__ import annotations
from pathlib import Path
from typing import Iterable, Set, LiteralString, List
import gzip

SNAP_DIR = Path("persist/snapshots")
SNAP_DIR.mkdir(parents=True, exist_ok=True)


def _snap_path(name: str) -> Path:
    return SNAP_DIR / f"{name}.ips.txt.gz"


def save_ip_snapshot(name: str, ips: Iterable[str]) -> None:
    p = _snap_path(name)
    p.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(p, "wt", encoding="utf-8") as f:
        for ip in ips:
            if ip:
                f.write(ip)
                f.write("\n")


def load_ip_snapshot(name: str|List[LiteralString]) -> Set[str]:
    p = _snap_path(name)
    if not p.exists():
        return set()
    out: Set[str] = set()
    with gzip.open(p, "rt", encoding="utf-8") as f:
        for line in f:
            ip = line.strip()
            if ip:
                out.add(ip)
    return out


def load_ip_snapshots(names: Iterable[str]) -> Set[str]:
    union: Set[str] = set()
    for name in names:
        s = load_ip_snapshot(name)
        if s:
            union |= s
    return union
