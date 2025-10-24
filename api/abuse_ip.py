import requests
from typing import Tuple, List, Optional

def fetch_abuseip_blacklist(abuseipdb_api_key: str, abuseipdb_url: str,
                            conf_min: int) -> Tuple[List[str], Optional[str]]:
    headers = {
        "Accept": "application/json",
        "Key": abuseipdb_api_key,
    }

    params = {
        "confidenceMinimum": str(conf_min),
        "limit": "500000"
    }

    resp = requests.get(abuseipdb_url, headers=headers, params=params, timeout=60)
    resp.raise_for_status()
    payload = resp.json()

    # IPs
    ips: List[str] = []
    for entry in (payload.get("data") or []):
        ip = entry.get("ipAddress")
        if ip:
            ips.append(ip)

    # meta.generatedAt
    meta = payload.get("meta") or {}
    generated_at = meta.get("generatedAt")
    return ips, generated_at