from typing import List

def chunk_list(items: List[str], size: int) -> List[List[str]]:
    if size <= 0:
        raise ValueError("size must be > 0")
    return [items[i:i+size] for i in range(0, len(items), size)]