"""Stable identity for findings across scans"""

import hashlib


def make_fingerprint(check_id: str, resources_arn: str) -> str:
    raw = f"{check_id}|{resources_arn}"

    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
