# CloudGuard Design (v1)

## Goal

CloudGuard scans a single AWS account once per day for common security misconfigurations, stores the results over time, and presents them on a web dashboard with plain-English explanations and fix guidance. It lets the account owner see at a glance what is wrong, what is new since the last scan, and what has been fixed. High-severity issues also trigger an email alert.

## System overview

```
EventBridge (daily) ──► Scanner (Lambda, read-only role)
                              │  runs every registered check
                              ▼
                         POST /scans ──► API (FastAPI) ──► PostgreSQL
                                              │
                                              ├──► LLM (explanations for NEW findings only, cached)
                                              ├──► SNS email (new critical/high findings)
                                              ▼
                                     Dashboard (React + TypeScript)
```

Responsibilities are deliberately split:

- **Scanner**: reads AWS and produces findings. It never writes to AWS and never touches the database.
- **API**: owns all state: deduplication, finding lifecycle, history, alerts, and AI explanations.
- **Dashboard**: read-only view of the API.

## Data model

### Finding

| Field | Type | Description |
|---|---|---|
| `fingerprint` | string (SHA-256 hex) | Stable identity of the issue across scans (see "Identifying the same finding") |
| `check_id` | string | ID of the check that produced it, e.g. `S3_PUBLIC_BUCKET` |
| `title` | string | Human-readable summary, e.g. "S3 bucket is publicly accessible" |
| `severity` | enum: `critical`, `high`, `medium`, `low` | See "Severity levels" |
| `resource_type` | string | e.g. `s3_bucket`, `security_group`, `iam_user` |
| `resource_id` | string | The resource's ARN |
| `account_id` | string | 12-digit AWS account ID |
| `region` | string | e.g. `us-east-1`, or `global` for IAM |
| `evidence` | JSON object | The specific settings that prove the issue (shape varies per check) |
| `status` | enum: `open`, `resolved` | Current state |
| `first_seen` | datetime (UTC) | First scan that detected it |
| `last_seen` | datetime (UTC) | Most recent scan that detected it |
| `resolved_at` | datetime (UTC), nullable | When it stopped being detected |
| `explanation` | JSON object, nullable | AI-generated risk/fix guidance (added in Phase 4) |

**Notes**

- `evidence` is JSON because every check proves its finding with different data.
- All timestamps are stored in UTC.

### Scan

Every run is recorded so the system knows which checks actually succeeded.

| Field | Type | Description |
|---|---|---|
| `scan_id` | UUID | Unique ID for the run |
| `account_id` | string | Account scanned |
| `started_at` / `finished_at` | datetime (UTC) | Run timing |
| `check_results` | list | One entry per check: `check_id`, `status` (`succeeded` / `failed`), `error` (nullable), `findings_count` |

## Identifying the same finding across scans

A finding's identity must be built only from values that do not change between scans:

```
fingerprint = sha256(check_id + "|" + resource_arn)
```

The ARN already encodes the account (and region where applicable), so the fingerprint is unique across the whole AWS footprint.

Deliberately **excluded** from the fingerprint:

- **Timestamps**: change on every scan, so every finding would look new.
- **Evidence**: details can change while the issue stays the same (e.g. a security group open on port 22 also gets port 3389 opened; that is still one "open to the internet" issue).
- **Severity**: rules may be re-tuned later; that must not turn old issues into new ones.

### Finding lifecycle

When the API ingests a scan, it applies these rules:

| Situation | Action |
|---|---|
| Fingerprint not in database | Insert as `open`; set `first_seen` = `last_seen` = scan time |
| Fingerprint exists and is `open` | Update `last_seen` and `evidence` |
| Fingerprint exists and is `resolved` | Reopen: set `status` = `open`, clear `resolved_at`, update `last_seen` |
| Fingerprint is `open` in database but absent from this scan | Mark `resolved`, set `resolved_at` = scan time, **only if the check that owns it succeeded in this scan** |

**Why the last condition matters:** if a check fails (permission error, AWS outage, bug), it returns no findings. Treating "no findings" as "fixed" would falsely resolve every open issue from that check. A failed check therefore leaves its findings untouched.

Ingestion is **idempotent**: posting the same scan twice produces the same database state.

## Check interface

Every check fits the same contract, so the scanner can run all of them in a loop without knowing their internals (plugin / registry pattern).

**Metadata** (describes the check itself):

- `id`: stable identifier, e.g. `SG_SSH_OPEN`
- `title`, `description`
- `resource_type`
- `severity`

**Behavior**:

- `run(session) -> list[Finding]`
  - **Input:** an AWS session **passed in** by the scanner (dependency injection). Checks never create their own sessions or read credentials.
  - **Output:** a list of findings. An empty list means the check passed.
  - **Errors:** a check raises an exception if it cannot complete. The scanner catches it, records the check as `failed`, and continues with the remaining checks.

**Rules for every check**

1. Read-only: uses only `Describe*`, `List*`, and `Get*` AWS calls.
2. Pure: returns data only. No printing, database writes, or notifications.
3. Handles AWS pagination so results are complete.

**Registry:** checks register themselves in a central list. Adding a check means writing one new module and registering it; the scanner core never changes.

**Why this design**

- **Extensible:** new checks don't touch existing code.
- **Testable:** because the session is injected, tests pass a mocked AWS (`moto`) containing deliberately misconfigured resources and assert on the returned findings.
- **Fault-isolated:** one failing check cannot stop the others.

## Initial checks

### 1. Public S3 bucket

- **ID:** `S3_PUBLIC_BUCKET`
- **Severity:** critical
- **Detects:** a bucket whose contents can be read by anyone on the internet.
- **AWS calls (`s3`, `s3control`):**
  - `s3control.get_public_access_block(AccountId=...)`: account-level Block Public Access (BPA)
  - `s3.list_buckets`
  - Per bucket: `get_bucket_location`, `get_public_access_block`, `get_bucket_policy_status`, `get_bucket_acl`
- **Fails if** either is true:
  - The bucket policy is public (`PolicyStatus.IsPublic == true`) **and** `RestrictPublicBuckets` is not enabled at the bucket or account level.
  - The ACL grants access to `http://acs.amazonaws.com/groups/global/AllUsers` or `.../AuthenticatedUsers` **and** `IgnorePublicAcls` is not enabled at the bucket or account level.
- **Edge cases:**
  - `NoSuchBucketPolicy` from `get_bucket_policy_status` means the bucket has no policy, so it is not public via policy. Not an error.
  - `NoSuchPublicAccessBlockConfiguration` means BPA is not configured at that level; treat all four BPA settings as `false`.
  - Since 2023, new buckets have BPA enabled by default, so a fresh account usually passes. The vulnerable lab (Phase 7) creates a public bucket for demos.
- **Evidence:** `{"policy_public": bool, "public_acl_grants": [...], "bucket_bpa": {...}, "account_bpa": {...}}`

### 2. SSH open to the internet

- **ID:** `SG_SSH_OPEN`
- **Severity:** high
- **Detects:** a security group that allows inbound SSH (port 22) from any IP address.
- **AWS calls (`ec2`):**
  - `describe_regions`: list enabled regions (security groups are regional)
  - Per region: `describe_security_groups` (paginated)
- **Fails if** any inbound rule in `IpPermissions` matches **both**:
  - **Port:** `IpProtocol == "-1"` (all traffic), **or** `IpProtocol == "tcp"` and `FromPort <= 22 <= ToPort`
  - **Source:** any `IpRanges[].CidrIp == "0.0.0.0/0"` (all IPv4) **or** any `Ipv6Ranges[].CidrIpv6 == "::/0"` (all IPv6)
- **Edge cases:**
  - Port ranges (e.g. 0–1000) include 22 and must be caught.
  - Protocol `"-1"` has no port numbers; it means every port.
  - Rules that reference other security groups or prefix lists are not "the internet" and are ignored in v1.
- **Evidence:** `{"group_id": ..., "group_name": ..., "vpc_id": ..., "matching_rules": [{"protocol": ..., "from_port": ..., "to_port": ..., "source": ...}]}`
- **Resource ARN:** `arn:aws:ec2:{region}:{account_id}:security-group/{group_id}`

### 3. IAM console user without MFA

- **ID:** `IAM_USER_NO_MFA`
- **Severity:** high
- **Detects:** an IAM user who can sign in to the AWS console with a password but has no MFA device.
- **AWS calls (`iam`, global):**
  - `list_users` (paginated)
  - Per user: `get_login_profile`, `list_mfa_devices`
- **Fails if:** the user has a login profile (console password) **and** `list_mfa_devices` returns no devices.
- **Edge cases:**
  - `get_login_profile` raising `NoSuchEntity` means the user has no console password (programmatic-only user). Skip; console MFA does not apply.
  - Users who sign in through IAM Identity Center are not IAM users and are not covered by this check.
- **Evidence:** `{"user_name": ..., "has_console_password": true, "mfa_devices": 0, "password_last_used": ...}`
- **Region:** `global`

### Required permissions

All calls above are read-only and covered by the AWS-managed `SecurityAudit` policy used for local development. In Phase 5, the Lambda role will be narrowed to exactly these actions:

```
s3:ListAllMyBuckets, s3:GetBucketLocation, s3:GetBucketPublicAccessBlock,
s3:GetBucketPolicyStatus, s3:GetBucketAcl, s3:GetAccountPublicAccessBlock,
ec2:DescribeRegions, ec2:DescribeSecurityGroups,
iam:ListUsers, iam:GetLoginProfile, iam:ListMFADevices
```

## Severity levels

| Level | Rule |
|---|---|
| **Critical** | Exposes data or access to the entire internet right now, with no other barrier |
| **High** | Makes an account takeover or breach significantly easier |
| **Medium** | Weakens defenses, but an attacker still needs something else |
| **Low** | Best-practice or hygiene issue |

| Check | Severity | Reason |
|---|---|---|
| `S3_PUBLIC_BUCKET` | Critical | Anyone can read the data immediately; no credentials or exploit needed. |
| `SG_SSH_OPEN` | High | The server is exposed to constant brute-force and exploit attempts, but an attacker still needs a valid key or a vulnerability to get in. |
| `IAM_USER_NO_MFA` | High | A single leaked or guessed password gives full console access with that user's permissions. |

Severity is fixed per check in v1. Context-aware severity (e.g. raising `IAM_USER_NO_MFA` to critical when the user has admin permissions, or lowering `SG_SSH_OPEN` when the group isn't attached to anything) is a planned improvement.

## Planned next checks

- Root account without MFA (`iam.get_account_summary` → `AccountMFAEnabled`)
- Access keys older than 90 days
- IAM policies granting `"Action": "*"` on `"Resource": "*"`
- Unencrypted EBS volumes
- RDP (port 3389) open to the internet
- CloudTrail not enabled

## Out of scope for v1

- **Automatic remediation.** The scanner is read-only by design; automatically changing resources is risky if a check is wrong. A future version may propose fixes as Terraform pull requests for human review.
- **Multiple AWS accounts.** v1 scans one account; multi-account scanning via AWS Organizations and cross-account roles is a planned extension.
- **Other cloud providers.** The check interface is provider-agnostic, so GCP or Azure checks could be added later.
- **Real-time detection.** v1 scans daily. Event-driven detection (e.g. reacting to CloudTrail events) is out of scope.
- **User accounts and multi-tenancy.** v1 is single-user.
