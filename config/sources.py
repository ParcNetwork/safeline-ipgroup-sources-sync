import yaml
import glob
import os

SOURCE_DIRS = [
    os.path.join("config", "sources.d"),   # Default configs
    os.path.join("config", "local.d"),     # User-specific overrides (optional)
]


def load_sources():
    merged = {}

    for directory in SOURCE_DIRS:
        if not os.path.isdir(directory):
            continue

        for path in glob.glob(os.path.join(directory, "*.yaml")):
            name = os.path.splitext(os.path.basename(path))[0]
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                merged[name] = data
            except Exception as e:
                print(f"[WARN] Failed to load {path}: {e}")

    return merged


SOURCES = load_sources()