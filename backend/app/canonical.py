import hashlib, json
from typing import Any

def canonical_json(report: dict[str, Any]) -> str:
    # Stable key ordering, UTF-8 characters preserved, no insignificant whitespace.
    return json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def report_sha256(report: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(report).encode("utf-8")).hexdigest()
