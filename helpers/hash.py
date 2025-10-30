from typing import Iterable
import hashlib, json

def _hash_list(values: Iterable[str]) -> str:
    normalized = sorted(values)
    h = hashlib.sha256(json.dumps(normalized, ensure_ascii=False).encode("utf-8"))
    return h.hexdigest()