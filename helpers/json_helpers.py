import requests
from typing import Tuple, List, Optional, Iterable
from helpers.creation_time import parse_creation_time

def fetch_json(url: str, timeout: int = 20) -> dict:
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    return r.json()

def extract_cidrs_from_json(data: dict, cidr_fields: Iterable[str] = None) -> List[str]:
    if cidr_fields is None:
        cidr_fields = {"ipv4Prefix", "ipv6Prefix"}

    cidrs: List[str] = []
    prefixes = data.get("prefixes") or data.get("ipRanges") or []

    for entry in prefixes:
        for field in cidr_fields:
            value = entry.get(field)
            if value:
                cidrs.append(value)

    return cidrs

def get_ip_ranges_and_ct(url: str) -> Tuple[List[str], Optional[str]]:
    data = fetch_json(url)
    creation_time = parse_creation_time(data)
    cidrs = extract_cidrs_from_json(data)
    return cidrs, creation_time