from typing import Dict, Iterable, Optional, Tuple
from helpers.hash import _hash_list

def decide_change(
    detector: str,
    state: Dict[str, object],
    *,
    state_key_ts: Optional[str],
    state_key_hash: str,
    new_ts: Optional[str],
    entries: Iterable[str],
) -> Tuple[bool, Dict[str, object]]:
    detector = (detector or "timestamp").lower()
    state_updates: Dict[str, object] = {}

    if detector == "hash" or (detector == "auto" and not new_ts):
        new_hash = _hash_list(entries)
        prev_hash = state.get(state_key_hash)
        if prev_hash == new_hash:
            if state_key_ts and new_ts:
                state_updates[state_key_ts] = new_ts
            return False, state_updates
        state_updates[state_key_hash] = new_hash
        if state_key_ts and new_ts:
            state_updates[state_key_ts] = new_ts
        return True, state_updates

    prev_ts = state.get(state_key_ts) if state_key_ts else None
    if state_key_ts is None or new_ts is None:
        return True, state_updates
    if prev_ts == new_ts:
        return False, state_updates
    state_updates[state_key_ts] = new_ts
    return True, state_updates