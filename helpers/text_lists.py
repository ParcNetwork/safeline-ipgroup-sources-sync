from __future__ import annotations
import requests
from typing import List

def fetch_text_lines(url: str, timeout: int = 20) -> List[str]:
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    lines: List[str] = []
    for raw in r.text.splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        lines.append(s)
    return lines