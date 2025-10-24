from typing import Any, Dict, List, Optional, TypedDict

class RuleExtract(TypedDict, total=False):
    id: Optional[int]
    name: str
    is_enabled: bool
    pattern: List[List[Dict[str, Any]]]
    auth_source_ids: Any
    action: Optional[int]
    action_policy: Optional[str]
    log: bool

def extract_rule_fields(rule: Dict[str, Any]) -> RuleExtract:
    action = rule.get("action", None)
    action_int = int(action) if isinstance(action, (int, str)) and str(action).isdigit() else None
    action_policy = {0: "allow", 1: "deny"}.get(action_int, None)

    return {
        "id": int(rule["id"]) if "id" in rule else None,
        "name": str(rule.get("name") or ""),
        "is_enabled": bool(rule.get("is_enabled", False)),
        "pattern": rule.get("pattern"),
        "auth_source_ids": rule.get("auth_source_ids"),
        "action": action_int,
        "action_policy": action_policy,
        "log": bool(rule.get("log", False)),
    }