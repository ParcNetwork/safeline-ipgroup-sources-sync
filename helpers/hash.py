import hashlib, json

def _hash_list(values: list[str]) -> str:
    h = hashlib.sha256(json.dumps(values, ensure_ascii=False).encode("utf-8"))
    return h.hexdigest()