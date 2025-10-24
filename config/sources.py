import yaml, glob, os


def load_sources():
    cfg = {}
    for path in glob.glob(os.path.join("config", "sources.d", "*.yaml")):
        name = os.path.splitext(os.path.basename(path))[0]
        with open(path, "r", encoding="utf-8") as f:
            cfg[name] = yaml.safe_load(f) or {}
    return cfg

SOURCES = load_sources()