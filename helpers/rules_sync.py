from __future__ import annotations
from typing import List, Dict, Any, Optional
from api.safeline import get_ip_group_id
from api.rules import get_rule_by_name, create_rule_minimal, update_rule_action, update_rule_ip_groups
from helpers import log


def group_ids_for_range(base_group: str, count: int) -> List[int]:
    ids: List[int] = []
    for idx in range(1, count + 1):
        name = f"{base_group}-{idx:03d}"
        gid = get_ip_group_id(name)
        if gid is not None:
            ids.append(int(gid))
    return ids


def ensure_rule_for_source(rule_name: str, policy: int, base_group: str,
                           rule_enabled: bool) -> int:
    rule = get_rule_by_name(rule_name)
    if not rule:
        gids = group_ids_for_range(base_group, 999)
        rid = create_rule_minimal(
            name=rule_name,
            policy=policy,
            enabled=True,
            ip_group_ids=gids
        )
        log.info("[RULE] created '%s' (ID %s) with %d groups", rule_name, rid, len(gids))
        return rid
    rid = int(rule["id"])
    if rule["action"] != policy or \
        rule["is_enabled"] is not rule_enabled:
        update_rule_action(policy, rule, rule_enabled)
    return rid


def sync_rule_to_used(rule_name: str, base_group: str, used_count: int) -> None:
    gids = group_ids_for_range(base_group, used_count)
    rule = get_rule_by_name(rule_name)
    if not rule:
        return
    update_rule_ip_groups(rule, gids)
    log.info("[RULE] '%s': set %d/%d groups", rule_name, len(gids), used_count)