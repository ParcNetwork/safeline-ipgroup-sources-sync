from typing import Iterable, List

def dedup_cidrs(cidrs: Iterable[str]) -> List[str]:
    return sorted(set(cidrs))