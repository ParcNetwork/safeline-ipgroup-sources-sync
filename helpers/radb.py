from __future__ import annotations
import socket
from typing import List
from helpers import log

def query_radb_origin(asn: str, server: str = "whois.radb.net", port: int = 43, timeout: float = 10.0) -> str:
    """
    Query RADB WHOIS for all prefixes originated by an ASN.
    Equivalent to: whois -h whois.radb.net -- '-i origin AS32934'
    Returns raw WHOIS response as text.
    """
    q = f"-i origin {asn}\r\n"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((server, port))
        s.sendall(q.encode("ascii"))
        chunks: List[bytes] = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
    finally:
        try:
            s.close()
        except Exception:
            pass

    # WHOIS often uses latin-1; fallback to utf-8
    raw = b"".join(chunks)
    try:
        return raw.decode("latin-1", errors="replace")
    except Exception:
        return raw.decode("utf-8", errors="replace")


def parse_radb_routes(whois_text: str) -> List[str]:
    """
    Parses 'route:' (IPv4) and 'route6:' (IPv6) lines into a list of CIDRs.
    Deduplicates while preserving order.
    """
    cidrs: List[str] = []
    seen = set()

    for line in whois_text.splitlines():
        line = line.strip()
        # data like: "route:  157.240.0.0/16" or "route6:  2a03:2880::/12"
        if line.lower().startswith("route:") or line.lower().startswith("route6:"):
            parts = line.split()
            if len(parts) >= 2:
                cidr = parts[1]
                if cidr not in seen:
                    seen.add(cidr)
                    cidrs.append(cidr)
    return cidrs


def get_radb_prefixes_for_asn(asn: str) -> List[str]:
    """
    Convenience: query + parse, with a tiny retry.
    """
    try:
        txt = query_radb_origin(asn)
        prefixes = parse_radb_routes(txt)
        if prefixes:
            return prefixes
        # If empty, retry once (transient whois hiccups happen)
        txt = query_radb_origin(asn)
        return parse_radb_routes(txt)
    except Exception as e:
        log.error("RADB WHOIS failed for %s: %s", asn, e)
        return []