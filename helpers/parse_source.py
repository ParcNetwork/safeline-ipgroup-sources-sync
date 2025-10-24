from __future__ import annotations
from typing import Dict, List, Optional, Any

from api.abuse_ip import fetch_abuseip_blacklist
from helpers.json_helpers import fetch_json, extract_cidrs_from_json
from helpers.grouping import upsert_grouped_entries, cleanup_extra_groups
from helpers.hash import _hash_list
from helpers.radb import get_radb_prefixes_for_asn
from config.credentials import settings

from helpers.rules_sync import sync_rule_to_used
from helpers.rule_init import ensure_rule_safe
from helpers import log


def process_source(name: str, cfg: Dict[str, Any], state: Dict[str, Any]) -> None:
    if not cfg.get("enabled", False):
        log.debug("%s: disabled", name)
        return

    kind = cfg["kind"]
    base_core = cfg["group_base"]
    base = f"parc_{base_core}"
    upload = cfg.get("upload", {}) or {}

    action_by_policy = {"allow": 0, "deny": 1} # mapping
    rules_cfg = cfg.get("rules") or {}
    rule_policy_str = rules_cfg.get("policy", "deny").lower()
    rule_policy = action_by_policy.get(rule_policy_str, 1)
    rule_name = rules_cfg.get("name", base)
    rule_enabled = rules_cfg.get("enabled")

    max_per_group = int(upload.get("max_per_group", 10_000))
    initial_batch_size = upload.get("initial_batch_size")
    append_batch_size = upload.get("append_batch_size")
    sleep_between_batches = upload.get("sleep_between_batches")
    cleanup_action = upload.get("cleanup")
    placeholder_ip = upload.get("placeholder_ip")

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
                rule_name=rule_name
            )

            _ = ensure_rule_safe(rule_name, rule_policy, base, rule_enabled)

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

        _ = ensure_rule_safe(rule_name, rule_policy, base, rule_enabled)

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

        _ = ensure_rule_safe(rule_name, rule_policy, base, rule_enabled)

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
    rule_name: str
) -> None:
    prev = state.get(url)
    if new_ts is None:
        log.warning("%s: no timestamp — process anyway.", url)
    elif prev == new_ts:
        log.info("%s: unchanged (%s) — skip.", url, new_ts)
        return
    else:
        log.info("%s: %s -> %s", url, prev, new_ts)

    prev_groups = int(state.get(f"{base_group}_group_count", 0))
    used = upsert_grouped_entries(
        entries=cidrs,
        base_group_name=base_group,
        max_per_group=max_per_group,
        initial_batch_size=int(initial_batch_size),
        append_batch_size=int(append_batch_size),
        sleep_between_batches=float(sleep_between_batches),
        placeholder_ip=placeholder_ip
    )

    cleanup_extra_groups(
        base_group_name=base_group,
        used_count=used,
        previous_count=prev_groups,
        placeholder_ip=placeholder_ip,
        action=cleanup_action
    )

    try:
        sync_rule_to_used(rule_name, base_group, used)
    except Exception as e:
        log.warning("rule sync failed for '%s': %s", rule_name, e)
    state[f"{base_group}_group_count"] = used
    if new_ts is not None:
        state[url] = new_ts

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

    from helpers.grouping import cleanup_extra_groups

    cleanup_extra_groups(
        base_group_name=base_group,
        used_count=used,
        previous_count=prev_groups,
        placeholder_ip=placeholder_ip,
        action=cleanup_action
    )

    try:
        sync_rule_to_used(rule_name, base_group, used)
    except Exception as e:
        log.warning("rule sync failed for '%s': %s", rule_name, e)

    state[f"{base_group}_group_count"] = used
    state[key] = new_hash

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
    prev_ct = state.get(state_key)
    prev_groups = int(state.get(f"{base_group}_group_count", 0))

    def run() -> int:
        return upsert_grouped_entries(
            entries=ips,
            base_group_name=base_group,
            max_per_group=max_per_group,
            initial_batch_size=initial_batch_size,
            append_batch_size=append_batch_size,
            sleep_between_batches=sleep_between_batches,
            placeholder_ip=placeholder_ip
        )

    if generated_at is None:
        log.warning("%s: no generatedAt — process anyway.", state_key)
        used = run()
        cleanup_extra_groups(
            base_group_name=base_group,
            used_count=used,
            previous_count=prev_groups,
            placeholder_ip=placeholder_ip,
            action=cleanup_action
        )

        state[f"{base_group}_group_count"] = used
        return

    if prev_ct == generated_at:
        log.info("%s: unchanged (%s) — skip.", state_key, generated_at)
        return

    log.info("%s: %s -> %s", state_key, prev_ct, generated_at)
    used = run()

    cleanup_extra_groups(
        base_group_name=base_group,
        used_count=used,
        previous_count=prev_groups,
        placeholder_ip=placeholder_ip,
        action=cleanup_action
    )

    try:
        sync_rule_to_used(rule_name, base_group, used)
    except Exception as e:
        log.warning("rule sync failed for '%s': %s", rule_name, e)

    state[state_key] = generated_at
    state[f"{base_group}_group_count"] = used