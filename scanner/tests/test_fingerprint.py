"""Tests for finding fingerprints."""

from cloudguard.fingerprint import make_fingerprint

SG_ARN = "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0abc123"
OTHER_SG_ARN = "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0def456"


def test_same_check_gives_same_fingerprint() -> None:
    first = make_fingerprint("SG_SSH_OPEN", SG_ARN)
    second = make_fingerprint("SG_SSH_OPEN", SG_ARN)

    assert first == second


def test_different_check_gives_different_fingerprint() -> None:
    ssh = make_fingerprint("SG_SSH_OPEN", SG_ARN)
    rdp = make_fingerprint("SG_RDP_OPEN", SG_ARN)

    assert ssh != rdp


def test_different_resource_gives_different_fingerprint() -> None:
    first = make_fingerprint("SG_SSH_OPEN", SG_ARN)
    second = make_fingerprint("SG_SSH_OPEN", OTHER_SG_ARN)

    assert first != second


def test_check_if_fingerprint_is_64_char_hex() -> None:
    fp = make_fingerprint("SG_SSH_OPEN", SG_ARN)

    assert len(fp) == 64
    assert all(c in "0123456789abcdef" for c in fp)
