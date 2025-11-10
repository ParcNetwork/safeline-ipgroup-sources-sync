from __future__ import annotations
from typing import Dict, List, Iterable, Optional

def parse_scored_lines(
    lines: Iterable[str],
    *,
    field_sep: str = "\t",
    ip_index: int = 0,
    score_index: int = 1,
    valid_levels: Optional[Iterable[int]] = None,
) -> Dict[int, List[str]]:
    level_map: Dict[int, List[str]] = {}
    valid = set(valid_levels) if valid_levels is not None else None

    for raw in lines:
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split(field_sep)
        if len(parts) <= max(ip_index, score_index):
            continue
        ip = parts[ip_index].strip()
        try:
            lvl = int(parts[score_index].strip())
        except ValueError:
            continue

        if valid is not None and lvl not in valid:
            continue

        level_map.setdefault(lvl, []).append(ip)

    for k, v in level_map.items():
        level_map[k] = sorted(set(v))
    return level_map