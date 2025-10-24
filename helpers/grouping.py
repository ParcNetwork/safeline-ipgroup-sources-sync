from __future__ import annotations
from math import ceil
from typing import Dict, Iterable, List, Optional, Literal
import time

from api.safeline import (
    get_ip_group_id,
    create_ip_group,
    update_ip_group,
    append_ip_group,
    delete_ip_group
)
from helpers.group_name import format_group_name
from helpers.chunks import chunk_list
from helpers import log

def stable_unique(seq: Iterable[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for x in seq or []:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def required_group_count(total_items: int, max_per_group: int) -> int:
    if total_items <= 0:
        return 0
    return ceil(total_items / max_per_group)

def ensure_group(group_name: str, placeholder_ip: List[str]) -> Optional[int]:
    gid = get_ip_group_id(group_name)
    if gid is not None:
        return gid
    try:
        gid = create_ip_group(group_name, placeholder_ip)
        log.info("Group '%s' created (ID %s).", group_name, gid)
        return gid
    except Exception as e:
        log.error("Could not create group '%s': %s", group_name, e)
        return None

def ensure_required_groups(base_group_name: str, count: int,
                           placeholder_ip: List[str]) -> Dict[int, int]:
    idx_to_gid: Dict[int, int] = {}
    for idx in range(1, count + 1):
        gname = format_group_name(base_group_name, idx)
        gid = ensure_group(gname, placeholder_ip)
        if gid is not None:
            idx_to_gid[idx] = gid
        else:
            log.warning("Missing group '%s' (create failed) — will skip its block.", gname)
    return idx_to_gid

def upload_replace(group_name: str, group_id: int, items: List[str]) -> None:
    update_ip_group(group_name, group_id, items)
    log.info("[REPLACE] %s: set %d entries", group_name, len(items))

def upload_hybrid(
    group_name: str,
    group_id: int,
    items: List[str],
    *,
    initial_batch_size: int,
    append_batch_size: int,
    sleep_between: float,
) -> None:
    items = stable_unique(items)
    if not items:
        log.debug("%s: no entries.", group_name)
        return

    first = items[:initial_batch_size] if initial_batch_size > 0 else []
    if first:
        update_ip_group(group_name, group_id, first)
        log.info("[UPDATE] %s: initial %d entries (replace)", group_name, len(first))
    else:
        update_ip_group(group_name, group_id, [])
        log.info("[UPDATE] %s: reset to %d entries", group_name, 0)

    rest = items[len(first):]
    if not rest:
        return

    if append_ip_group is None:
        update_ip_group(group_name, group_id, items)
        log.warning("[FALLBACK] %s: no append endpoint → full replace (%d)", group_name, len(items))
        return

    for i in range(0, len(rest), append_batch_size):
        chunk = rest[i: i + append_batch_size]
        append_ip_group(group_id, chunk)
        log.info("[APPEND] %s: +%d (batch %d)", group_name, len(chunk), i // append_batch_size + 1)
        if sleep_between > 0:
            time.sleep(sleep_between)

CleanupAction = Literal["delete", "placeholder", "clear", "keep"]

def cleanup_extra_groups(
    *,
    base_group_name: str,
    used_count: int,
    previous_count: int,
    action: str = "placeholder",
    placeholder_ip: str = "192.0.2.1",
) -> None:
    from api.safeline import count_groups_with_prefix, update_ip_group

    actual_count = count_groups_with_prefix(base_group_name)
    if actual_count <= used_count:
        log.info("[CLEANUP] %s: nothing to clean (actual=%d, used=%d)", base_group_name, actual_count, used_count)
        return

    log.info("[CLEANUP] %s: %d extra groups found (action=%s)", base_group_name, actual_count - used_count, action)

    for idx in range(used_count + 1, actual_count + 1):
        gname = f"{base_group_name}-{idx:03d}"
        gid = get_ip_group_id(gname)
        if gid is None:
            continue

        try:
            if action == "delete":
                delete_ip_group(gid)
                log.info("[DELETE] '%s' (ID %s) removed", gname, gid)
            elif action == "placeholder":
                update_ip_group(gname, gid, [placeholder_ip])
                log.info("[PLACEHOLDER] '%s' (ID %s) set to %s", gname, gid, placeholder_ip)
            elif action == "clear":
                update_ip_group(gname, gid, [])
                log.info("[CLEAR] '%s' (ID %s) cleared", gname, gid)
            else:
                log.debug("'%s': unknown action '%s'", gname, action)
        except Exception as e:
            log.warning("cleanup '%s' failed: %s", gname, e)

def upsert_grouped_entries(
    *,
    entries: List[str],
    base_group_name: str,
    max_per_group: int,
    initial_batch_size: int,
    append_batch_size: int,
    sleep_between_batches: float,
    placeholder_ip: str
) -> int:
    entries = stable_unique(entries)
    total = len(entries)
    if total == 0:
        log.info("%s: no entries to patch.", base_group_name)
        return 0

    blocks = chunk_list(entries, max_per_group)
    needed = required_group_count(total, max_per_group)
    idx_to_gid = ensure_required_groups(base_group_name, needed, [placeholder_ip])

    used = 0
    for idx, block in enumerate(blocks, start=1):
        gname = format_group_name(base_group_name, idx)
        gid = idx_to_gid.get(idx)
        if gid is None:
            log.debug("%s: missing group id — skip %d entries.", gname, len(block))
            continue

        log.info("[GROUP] %s: %d entries (block %d/%d)", gname, len(block), idx, len(blocks))
        upload_hybrid(
            group_name=gname,
            group_id=gid,
            items=block,
            initial_batch_size=initial_batch_size,
            append_batch_size=append_batch_size,
            sleep_between=sleep_between_batches,
        )
        used += 1

    return used