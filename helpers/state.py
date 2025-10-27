from __future__ import annotations
import os, json
from pathlib import Path
from typing import Dict

def _default_state_path() -> Path:
    """
    Priority:
    1) STATE_PATH env (explicit)
    2) ./persist/.ipranges_state.json (docker)
    3) ./.ipranges_state.json (project root)
    """
    env_path = os.environ.get("STATE_PATH")
    if env_path:
        return Path(env_path)

    persist_dir = Path("persist")
    try:
        persist_dir.mkdir(parents=True, exist_ok=True)
        return persist_dir / ".ipranges_state.json"
    except Exception:
        return Path(".ipranges_state.json")

STATE_PATH = _default_state_path()

def load_state() -> Dict:
    try:
        if STATE_PATH.exists():
            with STATE_PATH.open("r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}

def save_state(state: Dict) -> None:
    """
    keep save_state atomic if any error occur
    """
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_PATH.with_suffix(STATE_PATH.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)
    tmp.replace(STATE_PATH)