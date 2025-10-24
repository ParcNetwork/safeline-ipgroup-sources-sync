from typing import List
from helpers.dedup import dedup_cidrs
from helpers.group_name import group_name_for_url
from api.safeline import (
    get_ip_group_id,
    update_ip_group
)

from helpers import log

def patch_safeline_for_url(url: str, cidrs: List[str]) -> None:
    group_name = group_name_for_url(url)
    if not group_name:
        log.warning("No groups found for: %s — skipping.", url)
        return

    group_id = get_ip_group_id(group_name)
    if group_id is None:
        log.warning("SafeLine group '%s' not found — skipping.", group_name)
        return

    if not cidrs:
        log.info("Nothing to patch for '%s' — skipping.", group_name)
        return

    payload = dedup_cidrs(cidrs)
    log.info("%d CIDRs → Group '%s' (ID %s)", len(payload), group_name, group_id)
    update_ip_group(group_name, group_id, payload)