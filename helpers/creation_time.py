from typing import Optional

def parse_creation_time(data: dict) -> Optional[str]:
    return data.get("creationTime")