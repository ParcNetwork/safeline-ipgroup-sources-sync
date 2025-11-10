from __future__ import annotations
from typing import Dict, Any, List, Optional, Tuple

from helpers import log

from helpers.text_lists import fetch_text_lines
from helpers.ipsum.scored_lists import parse_scored_lines

from helpers.hash import _hash_list
from helpers.grouping import upsert_grouped_entries, cleanup_extra_groups
from helpers.rules_sync import sync_rule_to_used
from helpers.snapshot import load_ip_snapshots

RuleAction = Tuple[str, Optional[int], str, bool, int]

_ACTION_BY_POLICY = {"allow": 0, "deny": 1}


def process_ipsum_scored(
    name: str,
    cfg: Dict[str, Any],
    state: Dict[str, Any]
) -> List[RuleAction]:
    actions: List[RuleAction] = []

    base_core = cfg["group_base"]
    base_prefix = f"parc_{base_core}"

    urls = cfg.get("urls") or []
    if len(urls) != 1:
        log.warning("%s: txt-scored expects exactly one URL — got %d", name, len(urls))
        return actions
    url = urls[0]

    txt_def = cfg.get("txt", {}) or {}
    upload_def = cfg.get("upload", {}) or {}
    rules_def = cfg.get("rules", {}) or {}
    exclude_from = cfg.get("exclude_from")

    lvl_defs: List[Dict[str, Any]] = cfg.get("levels") or []
    if not lvl_defs:
        log.warning("%s: no 'levels' configured for txt-scored — skipping.", name)
        return actions

    wanted_levels = [int(ld["level"]) for ld in lvl_defs if ld.get("enabled", True)]
    if not wanted_levels:
        log.info("%s: no levels enabled — nothing to do.", name)
        return actions

    try:
        lines = fetch_text_lines(url)
    except Exception as e:
        log.error("%s: fetch failed for %s: %s", name, url, e)
        return actions

    level_map = parse_scored_lines(
        lines,
        field_sep=txt_def.get("field_sep", "\t"),
        ip_index=int(txt_def.get("ip_index", 0)),
        score_index=int(txt_def.get("score_index", 1)),
        valid_levels=wanted_levels,
    )

    for ld in lvl_defs:
        if not ld.get("enabled", True):
            continue

        level = int(ld["level"])
        ips = level_map.get(level, [])

        rules_cfg = {**rules_def, **(ld.get("rules") or {})}
        upload = {**upload_def, **(ld.get("upload") or {})}

        if isinstance(exclude_from, str):
            exclude_from = [exclude_from]

        exclude_from = [x.strip() for x in exclude_from if x and str(x).strip()]
        if exclude_from:
            exclude_set = load_ip_snapshots(exclude_from)
            if exclude_set:
                ips = [ip for ip in ips if ip not in exclude_set]

        base_group = f"{base_prefix}-l{level}"
        state_key = f"txtscored:{name}:{level}:{url}"

        new_hash = _hash_list(sorted(ips))
        prev_hash = state.get(state_key)

        policy_str = rules_cfg.get("policy", "").lower().strip()
        pol = _ACTION_BY_POLICY.get(policy_str) if policy_str else None
        rule_enabled = bool(rules_cfg.get("enabled", True))
        rule_name = rules_cfg.get("name", base_group)

        if prev_hash == new_hash:
            log.info("%s/l%d: unchanged — skip.", name, level)
            continue

        used = upsert_grouped_entries(
            entries=ips,
            base_group_name=base_group,
            max_per_group=int(upload.get("max_per_group", 10_000)),
            initial_batch_size=int(upload.get("initial_batch_size", 10_000)),
            append_batch_size=int(upload.get("append_batch_size", 500)),
            sleep_between_batches=float(upload.get("sleep_between_batches", 0.2)),
            placeholder_ip=upload.get("placeholder_ip", "192.0.2.1"),
        )

        actions.append((rule_name, pol, base_group, rule_enabled, used))

        try:
            sync_rule_to_used(rule_name, base_group, used)
        except Exception as e:
            log.warning("rule sync failed for '%s': %s", rule_name, e)

        prev_groups = int(state.get(f"{base_group}_group_count", 0))

        cleanup_extra_groups(
            base_group_name=base_group,
            used_count=used,
            previous_count=prev_groups,
            placeholder_ip=upload.get("placeholder_ip", "192.0.2.1"),
            action=upload.get("cleanup", "delete"),
        )

        state[state_key] = new_hash
        state[f"{base_group}_group_count"] = used

    return actions