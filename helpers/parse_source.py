from __future__ import annotations
from typing import Dict, List, Optional, Any

from api.abuse_ip import fetch_abuseip_blacklist
from api.rules import delete_rule
from helpers.json_helpers import fetch_json, extract_cidrs_from_json
from helpers.grouping import upsert_grouped_entries, cleanup_extra_groups
from helpers.hash import _hash_list
from helpers.radb import get_radb_prefixes_for_asn
from config.credentials import settings

from helpers.rules_sync import sync_rule_to_used
from helpers.rule_init import ensure_rule_safe
from helpers.dedup import dedup_cidrs
from helpers.change_detect import decide_change
from helpers import log
from helpers.text_lists import fetch_text_lines
from helpers.ipsum.process_ipsum import process_ipsum_scored


def process_source(name: str, cfg: Dict[str, Any], state: Dict[str, Any]) -> None:
    if not cfg.get("enabled", False):
        log.debug("%s: disabled", name)
        return

    kind = cfg["kind"]
    base_core = cfg["group_base"]
    base = f"parc_{base_core}"
    upload = cfg.get("upload", {}) or {}

    action_by_policy = {"allow": 0, "deny": 1}
    rules_cfg = cfg.get("rules") or {}
    rule_policy_str = rules_cfg.get("policy", "").lower()
    rule_policy = action_by_policy.get(rule_policy_str)
    rule_name = rules_cfg.get("name", base)
    rule_enabled = rules_cfg.get("enabled")

    max_per_group = int(upload.get("max_per_group", 10_000))
    initial_batch_size = upload.get("initial_batch_size")
    append_batch_size = upload.get("append_batch_size")
    sleep_between_batches = upload.get("sleep_between_batches")
    cleanup_action = upload.get("cleanup")
    placeholder_ip = upload.get("placeholder_ip")

    detector = cfg.get("change_detector", "timestamp").lower()

    if kind == "txt-scored":
        actions = process_ipsum_scored(name, cfg, state)
        for rule_name, rule_policy, base, rule_enabled in actions:
            if rule_policy is None:
                if delete_rule(rule_name):
                    log.info("%s: rule deleted (no policy in YAML)", rule_name)
                else:
                    log.debug("%s: no rule to delete (no policy in YAML)", rule_name)
            else:
                ensure_rule_safe(rule_name, rule_policy, base, rule_enabled)
        return

    if kind == "json-cidrs":
        json_cfg = cfg.get("json", {}) or {}
        ts_field = json_cfg.get("timestamp_field", "creationTime")
        cidr_fields = json_cfg.get("cidr_fields")

        for url in cfg["urls"]:
            data = fetch_json(url)
            new_ts = data.get(ts_field)
            cidrs = extract_cidrs_from_json(data, cidr_fields)
            _maybe_patch_json_source(
                url=url,
                cidrs=cidrs,
                new_ts=new_ts,
                base_group=base,
                state=state,
                placeholder_ip=placeholder_ip,
                max_per_group=max_per_group,
                initial_batch_size=initial_batch_size,
                append_batch_size=append_batch_size,
                sleep_between_batches=sleep_between_batches,
                cleanup_action=cleanup_action,
                rule_name=rule_name,
                change_detector=detector
            )

            if rule_policy is None:
                if delete_rule(rule_name):
                    log.info("%s: rule deleted (no policy in YAML)", rule_name)
                else:
                    log.debug("%s: no rule to delete (no policy in YAML)", rule_name)
            else:
                ensure_rule_safe(rule_name, rule_policy, base, rule_enabled)

    elif kind == "whois-radb":
        rconf = cfg.get("radb", {}) or {}
        asn = rconf.get("asn")

        if not asn:
            log.warning("%s: missing RADB ASN — skipping.", name)
            return

        cidrs = get_radb_prefixes_for_asn(asn)
        _maybe_patch_radb_source(
            asn=asn,
            base_group=base,
            state=state,
            cidrs=cidrs,
            placeholder_ip=placeholder_ip,
            max_per_group=max_per_group,
            initial_batch_size=initial_batch_size,
            append_batch_size=append_batch_size,
            sleep_between_batches=sleep_between_batches,
            cleanup_action=cleanup_action,
            rule_name=rule_name
        )

        if rule_policy is None:
            if delete_rule(rule_name):
                log.info("%s: rule deleted (no policy in YAML)", rule_name)
            else:
                log.debug("%s: no rule to delete (no policy in YAML)", rule_name)
        else:
            ensure_rule_safe(rule_name, rule_policy, base, rule_enabled)

    elif kind == "abuseipdb":
        p = cfg["api"]
        api_key = settings.ABUSEIPDB_KEY
        if not api_key:
            log.warning("%s: abuseipdb.api_key missing — skipping.", name)
            return

        ips, generated_at = fetch_abuseip_blacklist(
            api_key,
            p["url"],
            p["confidence_min"],
        )
        _maybe_patch_abuseip(
            state_key=p["url"],
            ips=ips,
            generated_at=generated_at,
            base_group=base,
            state=state,
            max_per_group=max_per_group,
            initial_batch_size=int(initial_batch_size) if initial_batch_size is not None else 500,
            append_batch_size=int(append_batch_size) if append_batch_size is not None else 500,
            sleep_between_batches=float(sleep_between_batches) if sleep_between_batches is not None else 0.4,
            cleanup_action=cleanup_action,
            placeholder_ip=placeholder_ip,
            rule_name=rule_name
        )

        if rule_policy is None:
            if delete_rule(rule_name):
                log.info("%s: rule deleted (no policy in YAML)", rule_name)
            else:
                log.debug("%s: no rule to delete (no policy in YAML)", rule_name)
        else:
            ensure_rule_safe(rule_name, rule_policy, base, rule_enabled)

    elif kind == "txt-cidrs":
        urls = cfg.get("urls") or []
        if not urls:
            log.warning("%s: no urls configured — skipping.", name)
            return

        _maybe_patch_txt_source(
            name=name,
            urls=urls,
            base_group=base,
            state=state,
            rule_name=rule_name,
            placeholder_ip=upload.get("placeholder_ip"),
            max_per_group=int(upload.get("max_per_group", 10_000)),
            initial_batch_size=int(upload.get("initial_batch_size", 10_000)),
            append_batch_size=int(upload.get("append_batch_size", 500)),
            sleep_between_batches=float(upload.get("sleep_between_batches", 0.2)),
            cleanup_action=upload.get("cleanup", "delete"),
        )

        if rule_policy is None:
            if delete_rule(rule_name):
                log.info("%s: rule deleted (no policy in YAML)", rule_name)
            else:
                log.debug("%s: no rule to delete (no policy in YAML)", rule_name)
        else:
            ensure_rule_safe(rule_name, rule_policy, base, rule_enabled)

    else:
        log.warning("%s: unknown kind '%s' – skipping.", name, kind)


def _maybe_patch_json_source(
    url: str,
    cidrs: List[str],
    new_ts: Optional[str],
    base_group: str,
    state: Dict[str, Any],
    placeholder_ip: str,
    *,
    max_per_group: int,
    initial_batch_size: Optional[int],
    append_batch_size: Optional[int],
    sleep_between_batches: Optional[float],
    cleanup_action: str,
    rule_name: str,
    change_detector: str = "timestamp"
) -> None:
    entries = dedup_cidrs(cidrs)

    state_key_ts = url
    state_key_hash = f"hash:{url}"

    should_update, state_updates = decide_change(
        detector=change_detector,
        state=state,
        state_key_ts=state_key_ts,
        state_key_hash=state_key_hash,
        new_ts=new_ts,
        entries=entries,
    )

    if not should_update:
        if change_detector == "hash" or (change_detector == "auto" and not new_ts):
            log.info("%s: unchanged (hash) — skip.", url)
        else:
            log.info("%s: unchanged (%s) — skip.", url, new_ts)
        state.update(state_updates)
        return

    used = upsert_grouped_entries(
        entries=cidrs,
        base_group_name=base_group,
        max_per_group=max_per_group,
        initial_batch_size=initial_batch_size,
        append_batch_size=append_batch_size,
        sleep_between_batches=sleep_between_batches,
        placeholder_ip=placeholder_ip,
    )

    try:
        sync_rule_to_used(rule_name, base_group, used)
    except Exception as e:
        log.warning("rule sync failed for '%s': %s", rule_name, e)

    prev_groups = int(state.get(f"{base_group}_group_count", 0))
    cleanup_extra_groups(
        base_group_name=base_group,
        used_count=used,
        previous_count=prev_groups,
        action=(cleanup_action or "delete"),
        placeholder_ip=(placeholder_ip or "192.0.2.1"),
    )

    state.update(state_updates)
    state[f"{base_group}_group_count"] = used
    state[f"{base_group}_count"] = len(entries)

    if "hash" in state_updates:
        log.info("%s: updated (hash changed, %d entries)", url, len(entries))
    else:
        log.info("%s: updated (%s -> %s, %d entries)",
                 url, state.get(state_key_ts), new_ts, len(entries))

def _maybe_patch_radb_source(
    *,
    asn: str,
    base_group: str,
    state: Dict[str, Any],
    cidrs: List[str],
    placeholder_ip: str,
    max_per_group: int,
    initial_batch_size: int,
    append_batch_size: int,
    sleep_between_batches: float,
    cleanup_action: str,
    rule_name: str
) -> None:
    key = f"radb:{asn}"
    new_hash = _hash_list(cidrs)
    prev_hash = state.get(key)

    if prev_hash == new_hash:
        log.info("RADB %s: unchanged — skip.", asn)
        return

    prev_groups = int(state.get(f"{base_group}_group_count", 0))

    used = upsert_grouped_entries(
        entries=cidrs,
        base_group_name=base_group,
        max_per_group=max_per_group,
        initial_batch_size=initial_batch_size,
        append_batch_size=append_batch_size,
        sleep_between_batches=sleep_between_batches,
        placeholder_ip=placeholder_ip,
    )

    try:
        sync_rule_to_used(rule_name, base_group, used)
    except Exception as e:
        log.warning("rule sync failed for '%s': %s", rule_name, e)

    cleanup_extra_groups(
        base_group_name=base_group,
        used_count=used,
        previous_count=prev_groups,
        placeholder_ip=placeholder_ip,
        action=cleanup_action
    )

    state[f"{base_group}_group_count"] = used
    state[key] = new_hash

def _maybe_patch_txt_source(
    *,
    name: str,
    urls: list[str],
    base_group: str,
    state: dict,
    rule_name: str,
    placeholder_ip: str | None,
    max_per_group: int,
    initial_batch_size: int,
    append_batch_size: int,
    sleep_between_batches: float,
    cleanup_action: str | None,
) -> None:
    all_lines: list[str] = []
    for u in urls:
        try:
            lines = fetch_text_lines(u)
            all_lines.extend(lines)
        except Exception as e:
            log.error("%s: fetch failed for %s: %s", name, u, e)
            continue

    unique_ips = dedup_cidrs(all_lines)
    key = f"txt:{name}"
    new_hash = _hash_list(unique_ips)
    prev_hash = state.get(key)

    if prev_hash == new_hash:
        log.info("%s: unchanged — skip.", name)
        return

    log.info("%s: hash changed", name)

    used = upsert_grouped_entries(
        entries=unique_ips,
        base_group_name=base_group,
        max_per_group=max_per_group,
        initial_batch_size=initial_batch_size,
        append_batch_size=append_batch_size,
        sleep_between_batches=sleep_between_batches,
        placeholder_ip=placeholder_ip,
    )

    try:
        sync_rule_to_used(rule_name, base_group, used)
    except Exception as e:
        log.warning("rule sync failed for '%s': %s", rule_name, e)

    prev_groups = int(state.get(f"{base_group}_group_count", 0))

    cleanup_extra_groups(
        base_group_name=base_group,
        used_count=used,
        previous_count=prev_groups,
        placeholder_ip=placeholder_ip,
        action=cleanup_action,
    )

    state[key] = new_hash
    state[f"{base_group}_group_count"] = used
    log.info("%s: updated (hash changed, %d entries)", key, len(unique_ips))


def _maybe_patch_abuseip(
    state_key: str,
    ips: List[str],
    generated_at: Optional[str],
    base_group: str,
    state: Dict[str, Any],
    *,
    max_per_group: int,
    initial_batch_size: int,
    append_batch_size: int,
    sleep_between_batches: float,
    cleanup_action: str,
    placeholder_ip: str,
    rule_name: str
) -> None:
    prev_groups = int(state.get(f"{base_group}_group_count", 0))

    unique_ips = dedup_cidrs(ips)
    new_hash = _hash_list(unique_ips)
    hash_state_key = f"{state_key}#hash"
    prev_hash = state.get(hash_state_key)

    if prev_hash == new_hash:
        log.info("%s: unchanged (hash) — skip.", state_key)
        if generated_at:
            state[state_key] = generated_at
        return

    used = upsert_grouped_entries(
        entries=unique_ips,
        base_group_name=base_group,
        max_per_group=max_per_group,
        initial_batch_size=initial_batch_size,
        append_batch_size=append_batch_size,
        sleep_between_batches=sleep_between_batches,
        placeholder_ip=placeholder_ip,
    )

    try:
        sync_rule_to_used(rule_name, base_group, used)
    except Exception as e:
        log.warning("rule sync failed for '%s': %s", rule_name, e)

    cleanup_extra_groups(
        base_group_name=base_group,
        used_count=used,
        previous_count=prev_groups,
        action=cleanup_action,
        placeholder_ip=placeholder_ip,
    )

    state[hash_state_key] = new_hash
    if generated_at:
        state[state_key] = generated_at
    state[f"{base_group}_group_count"] = used
    state[f"{base_group}_count"] = len(unique_ips)
    log.info("%s: updated (hash changed, %d entries)", state_key, len(unique_ips))