from typing import Optional

def group_name_for_url(url: str) -> Optional[str]:
    url = url.lower()
    mapping = {
        "googlebot": "googlebot",
        "special-crawlers": "google-special-crawlers",
        "bingbot": "bingbot",
        "duckduckbot": "duckduckbot",
        "gptbot": "gptbot",
        "ahrefs": "ahrefs",
        "facebook": "meta",
        "abuseip": "abuseip",
    }
    for key, value in mapping.items():
        if key in url:
            return value
    return None

def format_group_name(base: str, idx: int, width: int = 3) -> str:
    return f"{base}-{idx:0{width}d}"