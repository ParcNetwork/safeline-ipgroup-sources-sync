from __future__ import annotations
from typing import Optional, List
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

from config.credentials import settings

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE = settings.SAFELINE_BASE_URL.rstrip("/")
VERIFY_SSL = getattr(settings, "SAFELINE_VERIFY_SSL", False)
DEFAULT_TIMEOUT = float(getattr(settings, "SAFELINE_TIMEOUT", 30))

HDRS = {
    "X-SLCE-API-TOKEN": settings.SAFELINE_API_TOKEN,
    "accept": "application/json",
    "content-type": "application/json",
}

_session: requests.Session | None = None
def _session_with_retries() -> requests.Session:
    global _session
    if _session is not None:
        return _session
    s = requests.Session()
    retry = Retry(
        total=5,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST", "PUT", "DELETE"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    _session = s
    return s


def _request(method: str, path: str, **kwargs) -> requests.Response:
    s = _session_with_retries()
    url = f"{BASE}{path}"
    kwargs.setdefault("headers", HDRS)
    kwargs.setdefault("verify", VERIFY_SSL)
    kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
    resp = s.request(method=method, url=url, **kwargs)
    resp.raise_for_status()
    return resp


def get_ip_group_id(group_name: str) -> Optional[int]:
    resp = _request("GET", "/open/ipgroup")
    data = resp.json()
    for node in data.get("data", {}).get("nodes", []):
        if node.get("comment") == group_name:
            return int(node["id"])
    return None


def get_or_create_ip_group(group_name: str, bootstrap_ips: Optional[List[str]] = None) -> int:
    gid = get_ip_group_id(group_name)
    if gid is not None:
        return gid
    return create_ip_group(group_name, bootstrap_ips or [])


def create_ip_group(group_name: str, ips_to_add: List[str]) -> int:
    body = {
        "comment": group_name,
        "ips": ips_to_add or [],
    }
    resp = _request("POST", "/open/ipgroup", json=body)
    data = resp.json()
    new_id = data.get("data")
    if new_id is None:
        gid = get_ip_group_id(group_name)
        if gid is None:
            raise RuntimeError(f"Group '{group_name}' created but ID not returned and not found.")
        return gid
    return int(new_id)


def update_ip_group(ip_group_name: str, ip_group_id: int, ips_to_set: List[str]) -> None:
    if ips_to_set is None:
        ips_to_set = []
    body = {
        "id": ip_group_id,
        "reference": "",
        "comment": ip_group_name,
        "ips": ips_to_set,
    }
    _request("PUT", "/open/ipgroup", json=body)


def append_ip_group(ip_group_id: int, ips_to_add: List[str]) -> None:
    ips_to_add = ips_to_add or []
    if not ips_to_add:
        return
    body = {
        "ip_group_ids": [ip_group_id],
        "ips": ips_to_add,
    }
    _request("POST", "/open/ipgroup/append", json=body)


def delete_ip_group(gid: int) -> bool:
    body = {"ids": [gid]}
    _request("DELETE", "/open/ipgroup", json=body)
    return True

def count_groups_with_prefix(base: str) -> int:
    resp = _request("GET", "/open/ipgroup")
    data = resp.json()
    prefix = f"{base}-"
    count = 0
    for node in data.get("data", {}).get("nodes", []):
        comment = node.get("comment", "")
        if isinstance(comment, str) and comment.startswith(prefix):
            count += 1
    return count