from __future__ import annotations

from helpers.rules_sync import ensure_rule_for_source
from helpers import log

def ensure_rule_safe(rule_name: str, rule_policy: int, base: str, enabled: bool | None) -> bool:
    try:
        _ = ensure_rule_for_source(rule_name, rule_policy, base, enabled)
        return True
    except Exception as e:
        log.warning("ensure_rule_for_source failed for '%s': %s", rule_name, e)
        return False