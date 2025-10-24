from __future__ import annotations
from typing import List, Dict, Any, Optional
from api.safeline import _request
from helpers.classes.rule_extract import extract_rule_fields

RULES_ENDPOINT = "/open/policy"


def list_rules() -> List[Dict[str, Any]]:
    resp = _request("GET", f"{RULES_ENDPOINT}?action=-1")
    data = resp.json()
    return data.get("data", {}).get("data", []) or []


def get_rule_by_name(name: str) -> Optional[Dict[str, Any]]:
    for r in list_rules():
        if r.get("name") == name:
            return r
    return None


def create_rule_minimal(*, name: str, policy: int, enabled: bool = True,
                        ip_group_ids: Optional[List[int]] = None) -> int:
    body = {
        "name": name,
        "action": policy,
        "is_enabled": bool(enabled),
    }
    if ip_group_ids:
        body["ip_group_ids"] = [int(x) for x in ip_group_ids]
        body["pattern"] = [[{"k": "src_ip", "op": "in", "v": [str(i) for i in ip_group_ids], "sub_k": ""}]]
    resp = _request("POST", RULES_ENDPOINT, json=body)
    js = resp.json()
    d = js.get("data")
    if isinstance(d, int):
        return int(d)
    if isinstance(d, dict) and isinstance(d.get("id"), int):
        return int(d["id"])
    raise RuntimeError(f"Unexpected rule-create response: {js!r}")


def update_rule_ip_groups(rule: dict[str, Any], group_ids: list[int]) -> None:
    fields = extract_rule_fields(rule)
    pattern = [[{"k": "src_ip", "op": "in", "v": [str(i) for i in group_ids], "sub_k": ""}]]
    body = {
        "id": fields["id"],
        "name": fields["name"],
        "is_enabled": fields["is_enabled"],
        "pattern": pattern,
        "auth_source_ids": fields["auth_source_ids"],
        "action": fields["action"],
        "log": fields["log"],
    }
    _request("PUT", RULES_ENDPOINT, json=body)


def update_rule_action(policy: int, rule: dict[str, Any],
                       rule_enabled: bool) -> None:
    fields = extract_rule_fields(rule)
    body = {
        "id": fields["id"],
        "name": fields["name"],
        "is_enabled": rule_enabled,
        "pattern": fields["pattern"],
        "auth_source_ids": fields["auth_source_ids"],
        "action": policy,
        "log": fields["log"],
    }
    _request("PUT", RULES_ENDPOINT, json=body)