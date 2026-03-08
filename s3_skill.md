# S3 Security Analysis Skill — Attack Path Edition

## Service Overview

S3 is the primary data storage surface in most AWS accounts. A single bucket misconfiguration can expose customer data, backups, audit logs, application secrets, or infrastructure state to the internet or to unauthorized cross-account access. S3 findings should not be evaluated by a single signal like `Principal: *` — always evaluate the full access path.

This skill is designed for the **primary-service + dependency-context model** defined in CLAUDE.md. The S3 scanner Python file runs AWS CLI commands for S3 (primary) plus minimal dependency context from IAM, CloudTrail, and other services. This skill tells CloudSentinel how to interpret all of that input and produce evidence-based findings and attack paths.

Primary goals:
1. Identify public or broadly accessible buckets
2. Distinguish read vs write vs delete exposure
3. Evaluate data protection (encryption, versioning, MFA Delete)
4. Assess visibility and auditability
5. Detect cross-account and cross-service abuse paths

---

## 1. Input Layout and Interpretation

The S3 scanner Python file runs AWS CLI commands and delivers output in this structure:

```text
=== PRIMARY SERVICE: S3 ===
--- Command: list-buckets ---
[output]
--- Command: get-public-access-block (account-level via s3control) ---
[output]
--- Command: get-public-access-block (per bucket) ---
[output]
--- Command: get-bucket-policy (per bucket) ---
[output]
--- Command: get-bucket-policy-status (per bucket) ---
[output]
--- Command: get-bucket-acl (per bucket) ---
[output]
--- Command: get-bucket-encryption (per bucket) ---
[output]
--- Command: get-bucket-versioning (per bucket) ---
[output]
--- Command: get-bucket-logging (per bucket) ---
[output]
--- Command: get-bucket-tagging (per bucket) ---
[output]
--- Command: get-bucket-website (per bucket) ---
[output]
--- Command: get-bucket-ownership-controls (per bucket) ---
[output]
--- Command: get-bucket-replication (per bucket) ---
[output]
--- Command: get-bucket-notification-configuration (per bucket) ---
[output]

=== DEPENDENCY CONTEXT: IAM ===
--- Command: list-roles (roles with S3 trust or S3-heavy policies) ---
[output]
--- Command: get-role (per S3-relevant role) ---
[output]
--- Command: list-attached-role-policies (per S3-relevant role) ---
[output]
--- Command: get-policy-version (per significant S3-related policy) ---
[output]
--- Command: list-users (users with S3-heavy policies) ---
[output]

=== DEPENDENCY CONTEXT: CLOUDTRAIL ===
--- Command: describe-trails ---
[output]
--- Command: get-trail-status (per trail) ---
[output]
--- Command: get-event-selectors (per trail — S3 data events) ---
[output]

=== DEPENDENCY CONTEXT: EC2 ===
--- Command: describe-instances (instances with roles that access S3) ---
[output]

=== DEPENDENCY CONTEXT: LAMBDA ===
--- Command: list-functions (functions with roles that access S3) ---
[output]
```

### Input Interpretation Rules

1. **PRIMARY SERVICE: S3** is the full audit scope. Every bucket and its configuration in this section must be analyzed.
2. **DEPENDENCY CONTEXT** sections are supporting evidence only. Use them to validate or disprove S3-centered attack paths (e.g., which IAM roles can access exposed buckets, whether CloudTrail monitors S3 data events, whether EC2 instances or Lambda functions use S3).
3. Do NOT perform a standalone IAM, EC2, or Lambda audit from dependency context.
4. Do NOT emit findings for dependency services unless a dependency misconfiguration is directly required to explain an S3-centered attack path.
5. If a dependency section is missing or empty, do not assume it is secure or insecure. State what could not be evaluated.
6. Do NOT invent resources, permissions, trust relationships, or policy statements not visible in the input.

### Output Contract Guardrails

- Return **valid JSON only**. Do not emit markdown fences or prose outside the JSON object.
- `findings[].severity` must always be one of `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.
- If evidence is ambiguous, keep the best-fit severity and set `findings[].status` to `NEEDS_REVIEW`. Never use `NEEDS_REVIEW` as a severity.
- `quick_wins[]` entries must include `finding_id`, `action`, `effort`, and `impact`.
- `attack_paths[].id` must use `AP-{NUMBER}`, and every `full_path_summary` must use real bucket names or other real resource identifiers from the scan.

---

## 2. Relationship Mapping (Do This First)

Before generating any findings or attack paths, build these maps from the scan data:

### S3 Resource Maps
- **Bucket → Public Access Block**: account-level and bucket-level settings (all four flags)
- **Bucket → Policy**: parsed policy statements with principals, actions, resources, and conditions
- **Bucket → ACL**: grantee URIs (AllUsers, AuthenticatedUsers, specific accounts)
- **Bucket → Effective Public Status**: combining access block + policy + ACL to determine real exposure
- **Bucket → Encryption**: SSE-S3, SSE-KMS, or none
- **Bucket → Versioning**: enabled, suspended, or not configured
- **Bucket → Logging**: logging target bucket or not enabled
- **Bucket → Website Hosting**: enabled or not
- **Bucket → Ownership Controls**: BucketOwnerEnforced, BucketOwnerPreferred, or ObjectWriter
- **Bucket → Sensitivity Classification**: inferred from name, tags, and controls (see Sensitive Bucket Heuristics)
- **Bucket → Replication**: cross-region or cross-account replication configured

### Access Evaluation Order (Per Bucket)
Evaluate in this sequence to determine real exposure:
1. Account-level Public Access Block → blocks all public access if enabled
2. Bucket-level Public Access Block → blocks public access for this bucket if enabled
3. Explicit Deny in bucket policy → overrides allows
4. Allow statements in bucket policy → check principals, actions, conditions
5. ACL grants → AllUsers, AuthenticatedUsers
6. IAM permissions for authenticated principals (from dependency context)
7. Conditions → VPC endpoint, SourceIp, SourceArn, SourceAccount, OrgID restrictions

**A bucket is meaningfully public only when**: account-level controls do not block it, bucket-level controls do not block it, AND policy or ACL grants access to unauthenticated or overly broad principals.

### Dependency Maps (from dependency context)
- **IAM Roles/Users → S3 Permissions**: which identities can read/write/delete/admin specific buckets
- **IAM Roles on EC2 Instances → S3 Access**: which running instances can access which buckets (and whether those instances are public)
- **IAM Roles on Lambda Functions → S3 Access**: which functions can access which buckets
- **CloudTrail → S3 Data Events**: whether S3 object-level access is logged

### Derived Relationships
- **Publicly Accessible Sensitive Buckets**: public exposure + sensitive name/tags
- **Write-Exposed Buckets**: broad principals with PutObject/DeleteObject/PutBucketPolicy
- **Unmonitored Exposed Buckets**: public or broadly accessible + no logging + no CloudTrail data events
- **Instance-to-Bucket Chains**: public EC2 instances whose roles can access sensitive buckets

---

## 3. S3 Direct Findings — Misconfiguration Patterns

These are direct findings in the primary S3 service. Each pattern produces a `findings[]` entry.

### Pattern S3-ACCOUNT-PAB: Account-Level Public Access Block Disabled
- **Detection**: `s3control get-public-access-block` fails or all four settings are `false`
- **Category**: `access_control`
- **Base severity**: CRITICAL
- **Blast radius**: Account-wide — every bucket loses this safety net
- **Impact**: Removes the account-wide safety net that prevents accidental public exposure across all buckets. One policy mistake on any bucket can become internet exposure.
- **Fix**: `aws s3control put-public-access-block --account-id {account-id} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`
- **Attack path role**: Enabler for all public exposure chains

### Pattern S3-BUCKET-PUBLIC-READ: Bucket Publicly Readable
- **Detection**: `get-bucket-policy-status` shows `IsPublic: true` with read actions, OR policy/ACL grants `s3:GetObject` to `Principal: *` without restrictive conditions, AND access blocks do not neutralize
- **Category**: `data_exposure`
- **Base severity**:
  - CRITICAL if bucket appears sensitive (name/tag heuristics)
  - HIGH if bucket is intentional website/static asset with limited read-only scope
  - LOW if clearly intentional public hosting with safe scope
- **Status rule**: Use `NEEDS_REVIEW` when the bucket appears intentionally public but the available evidence is insufficient to prove the content is safe and expected.
- **Impact**: Direct internet access to read bucket contents — data breach if sensitive
- **Fix**: Enable bucket-level public access block, or restrict policy principal
- **Attack path role**: Direct data exfiltration endpoint — no compromise chain needed

### Pattern S3-BUCKET-PUBLIC-WRITE: Bucket Publicly Writable
- **Detection**: Policy grants `s3:PutObject`, `s3:DeleteObject`, `s3:PutBucketPolicy`, `s3:PutObjectAcl`, or `s3:*` to `Principal: *` or broad principals without restrictive conditions
- **Category**: `data_exposure`
- **Base severity**: CRITICAL
- **Impact**: Enables ransomware-style overwrite, malicious content hosting, policy tampering, or persistence. Bucket-wide impact; may become account-impacting if the bucket stores code, logs, or app artifacts.
- **Fix**: Remove broad write permissions, restrict to specific principals
- **Attack path role**: Write access enables data destruction, content injection, and persistence

### Pattern S3-PUBLIC-ACL: Public ACL Grants Access
- **Detection**: ACL grantee URI includes `AllUsers` or `AuthenticatedUsers`
- **Category**: `data_exposure`
- **Base severity**:
  - CRITICAL if public access block does not neutralize the ACL
  - LOW or no finding if account/bucket settings fully ignore public ACLs
- **Impact**: Legacy public access path that is often forgotten and hard to notice in reviews
- **Fix**: `aws s3api put-bucket-acl --bucket {bucket} --acl private`
- **Attack path role**: Alternative public exposure path bypassing policy review

### Pattern S3-BROAD-PRINCIPAL: Bucket Policy Uses Broad Principal Without Restrictive Conditions
- **Detection**: `"Principal": "*"` or wildcard AWS principals with no meaningful Condition (no VPC endpoint, no SourceIp, no OrgID, no SourceArn)
- **Category**: `access_control`
- **Base severity**:
  - CRITICAL for broad read on sensitive bucket
  - CRITICAL for broad write/delete on any bucket
  - HIGH for broad read on low-sensitivity public-content bucket
- **Impact**: Anyone or overly broad identities can access the bucket
- **Fix**: Replace wildcard principals with specific principals, accounts, roles, or restrictive conditions

### Pattern S3-CROSS-ACCOUNT: Cross-Account Access Without Tight Conditions
- **Detection**: Bucket policy grants access to external AWS accounts, roles, or roots without strong conditions
- **Category**: `access_control`
- **Base severity**: HIGH if cross-account appears intentional but weakly scoped; HIGH if external write is broadly allowed; CRITICAL if external broad access + sensitive bucket
- **Status rule**: Use `NEEDS_REVIEW` when cross-account access appears intentional but the business justification or exact guardrails cannot be validated from the scan.
- **Impact**: Data may be exposed or writable from another AWS account
- **Fix**: Scope to exact role ARNs, add `aws:PrincipalArn`, `aws:PrincipalOrgID`, `aws:SourceArn`, or prefix restrictions

### Pattern S3-BUCKET-PAB: Bucket-Level Public Access Block Disabled
- **Detection**: `get-public-access-block` missing or all four flags `false`
- **Category**: `access_control`
- **Base severity**: HIGH
- **Severity modifiers**: Raise if policy/ACL is already broad; lower if bucket is clearly intentional public website
- **Impact**: Removes local safety net — any policy or ACL granting public access will take effect
- **Fix**: `aws s3api put-public-access-block --bucket {bucket} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`

### Pattern S3-NO-ENCRYPTION: Default Encryption Not Configured
- **Detection**: `get-bucket-encryption` returns `ServerSideEncryptionConfigurationNotFoundError`
- **Category**: `encryption`
- **Base severity**: HIGH for sensitive buckets; MEDIUM for general production buckets
- **Impact**: Objects can be stored without encryption at rest by default
- **Fix**: `aws s3api put-bucket-encryption --bucket {bucket} --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'`
- **Note**: SSE-S3 is acceptable baseline; SSE-KMS is stronger for auditability and key control

### Pattern S3-SSE-S3-ONLY: Encryption Uses SSE-S3 Instead of SSE-KMS
- **Detection**: Encryption configuration uses `AES256`
- **Category**: `encryption`
- **Base severity**: LOW for general buckets; MEDIUM for sensitive or regulated buckets
- **Impact**: Encryption exists but key-level access control, auditability, and revocation are weaker
- **Fix**: Consider migrating sensitive buckets to SSE-KMS with customer-managed keys

### Pattern S3-NO-VERSIONING: Versioning Not Enabled
- **Detection**: `get-bucket-versioning` is empty or not `Enabled`
- **Category**: `backup_recovery`
- **Base severity**: MEDIUM for production/backup/logs/audit/sensitive buckets; LOW for temporary/static content
- **Impact**: Weak recovery posture against accidental deletion, malicious overwrite, and ransomware-style object replacement
- **Fix**: `aws s3api put-bucket-versioning --bucket {bucket} --versioning-configuration Status=Enabled`

### Pattern S3-NO-MFA-DELETE: MFA Delete Not Enabled on Important Versioned Buckets
- **Detection**: Versioning enabled but `MFADelete` missing or not enabled
- **Category**: `backup_recovery`
- **Base severity**: MEDIUM; raise to HIGH for critical backups or irreplaceable data
- **Impact**: Attackers with API credentials may purge versions without MFA
- **Fix note**: Requires root account credentials and operational care

### Pattern S3-NO-LOGGING: Logging Not Enabled
- **Detection**: `get-bucket-logging` returns no `LoggingEnabled`
- **Category**: `logging_monitoring`
- **Base severity**: MEDIUM for sensitive or internet-accessible buckets; LOW for low-risk buckets
- **Impact**: Weakens forensic visibility into bucket access patterns
- **Fix**: `aws s3api put-bucket-logging --bucket {bucket} --bucket-logging-status '{"LoggingEnabled":{"TargetBucket":"{log-bucket}","TargetPrefix":"{bucket}/"}}'`

### Pattern S3-OWNERSHIP-NOT-ENFORCED: Object Ownership Not Enforced
- **Detection**: `get-bucket-ownership-controls` missing or not `BucketOwnerEnforced`
- **Category**: `access_control`
- **Base severity**: MEDIUM
- **Impact**: ACLs remain active and object ownership can become confusing in multi-writer environments, increasing access-control mistakes
- **Fix**: `aws s3api put-bucket-ownership-controls --bucket {bucket} --ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerEnforced}]'`

### Pattern S3-WEBSITE-RISKY: Static Website Hosting on Non-Public-Controlled Bucket
- **Detection**: `get-bucket-website` succeeds on a bucket that lacks clear public-read intent or safe controls
- **Category**: `data_exposure`
- **Base severity**: LOW if website hosting seems intentional; HIGH if bucket is sensitive and website mode is inconsistent with purpose
- **Status rule**: Use `NEEDS_REVIEW` when website hosting appears intentional but the scan does not prove whether the bucket only serves expected public content.
- **Impact**: Website buckets are often publicly exposed and can become data-leak or defacement surfaces

### Pattern S3-NO-REPLICATION: No Replication on Critical Data Buckets
- **Detection**: `get-bucket-replication` missing for obvious backup/audit/critical buckets
- **Category**: `backup_recovery`
- **Base severity**: LOW to MEDIUM depending on bucket importance
- **Note**: Resilience-oriented, not a direct exposure finding

### Pattern S3-NO-TAGS: Missing Tags on Production-Relevant Buckets
- **Detection**: `get-bucket-tagging` missing or empty
- **Category**: `resource_hygiene`
- **Base severity**: LOW

---

## 4. S3 Attack Path Reference Catalog

These are the **reference attack paths** that CloudSentinel should attempt to match against actual scan evidence. A path from this catalog may ONLY be emitted as a formal `attack_paths[]` entry if it meets the evidence threshold from CLAUDE.md:

- At least **2 CONFIRMED hops**
- No more than **1 critical unexplained inference**
- Path is specific to actual resources found in the scan

---

### AP-REF-01: Public Sensitive Bucket Direct Data Breach

**Pattern**: Internet → Public Bucket Policy/ACL → Read Sensitive Data

**Chain hops**:
1. **Account Safety Net Missing**: Account-level public access block is disabled or partially disabled
2. **Bucket Exposed**: Bucket-level public access block is disabled or missing
3. **Public Read**: Bucket policy or ACL grants `s3:GetObject` (or broader) to `Principal: *` without restrictive conditions
4. **Sensitive Data**: Bucket name/tags suggest sensitive content (prod, backup, customer, db, finance, etc.)

**Evidence requirements**:
- Hop 1 CONFIRMED: account-level public access block status in scan
- Hop 2 CONFIRMED: bucket-level public access block status in scan
- Hop 3 CONFIRMED: policy or ACL analysis shows public read access
- Hop 4 CONFIRMED if bucket name/tags clearly indicate sensitivity; INFERRED if name is ambiguous

**Minimum for formal path**: Hops 2 and 3 must be CONFIRMED (bucket exposure is proven). Hop 1 strengthens the path but is not strictly required if bucket-level controls are the relevant gap.

**Impact**: Any internet user can download objects from the bucket. If the bucket contains customer data, backups, credentials, financial records, or application secrets, this is a direct data breach.

**Remediation priority**:
1. Enable public access block on the bucket immediately
2. Enable account-level public access block
3. Remove public principal from bucket policy/ACL
4. Audit bucket contents for leaked credentials and rotate them

---

### AP-REF-02: Public Write Access — Ransomware and Content Injection

**Pattern**: Internet → Public Write to Bucket → Object Overwrite / Malicious Upload / Policy Tampering

**Chain hops**:
1. **Bucket Exposed**: Public access blocks do not prevent write access
2. **Write Permission**: Bucket policy grants `s3:PutObject`, `s3:DeleteObject`, `s3:PutBucketPolicy`, or `s3:*` to `Principal: *`
3. **No Versioning**: Versioning is disabled, so overwrites destroy the original data
4. **No Logging**: Bucket logging is disabled, so the attack may go undetected

**Evidence requirements**:
- Hop 1 CONFIRMED: public access block analysis shows write not blocked
- Hop 2 CONFIRMED: policy shows public write actions
- Hop 3 CONFIRMED: versioning status in scan shows disabled/not configured
- Hop 4 CONFIRMED: logging status in scan shows not enabled

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED.

**Impact**: Attacker can overwrite objects (ransomware-style destruction), upload malicious content (phishing pages, malware), inject JavaScript into web-served content (supply chain attack), or modify the bucket policy itself to establish persistence. Without versioning, overwritten data cannot be recovered.

**Remediation priority**:
1. Remove public write permissions immediately
2. Enable public access block
3. Enable versioning as a safety net
4. Enable logging for forensic visibility

---

### AP-REF-03: Cross-Account Bucket Access to Data Exfiltration

**Pattern**: External Account → Cross-Account Bucket Policy → Read/Copy Sensitive Data

**Chain hops**:
1. **Cross-Account Trust**: Bucket policy grants access to an external AWS account (different account ID in principal)
2. **Weak Conditions**: No external ID, no OrgID, no SourceArn, or overly broad conditions
3. **Sensitive Actions**: Allowed actions include `s3:GetObject`, `s3:ListBucket`, or broader
4. **Sensitive Bucket**: Bucket contains sensitive data (name/tag heuristics)

**Evidence requirements**:
- Hop 1 CONFIRMED: bucket policy shows external account ID in principal
- Hop 2 CONFIRMED: condition analysis shows missing or weak restrictions
- Hop 3 CONFIRMED: allowed actions visible in policy
- Hop 4 CONFIRMED if name/tags clearly indicate sensitivity; INFERRED if ambiguous

**Minimum for formal path**: Hops 1, 2, and 3 must be CONFIRMED.

**Impact**: If the external account is compromised, attackers can read or list objects in the bucket. Without tight conditions, any principal in the external account can access the data.

**Remediation priority**:
1. Add restrictive conditions (OrgID, specific role ARN, external ID)
2. Scope allowed actions to minimum required
3. Enable bucket logging to monitor cross-account access
4. Review whether cross-account access is still needed

---

### AP-REF-04: EC2 Instance Role to S3 Data Exfiltration (Cross-Service)

**Pattern**: Compromised EC2 Instance → IAM Role → S3 Read/Write → Data Exfiltration

**Chain hops**:
1. **Entry**: EC2 instance is internet-reachable (from EC2 dependency context: public IP + open SG)
2. **Host Compromise**: Attacker gains instance access
3. **IAM Role**: Instance role has `s3:GetObject`, `s3:PutObject`, `s3:ListBucket`, or `s3:*` permissions targeting specific buckets or wildcard
4. **S3 Target**: Target bucket exists and contains data (from primary S3 scan)

**Evidence requirements**:
- Hop 1 CONFIRMED: EC2 dependency context shows public instance with open SG
- Hop 2 INFERRED: standard assumption from internet exposure
- Hop 3 CONFIRMED: IAM dependency context shows role policy with S3 actions
- Hop 4 CONFIRMED: bucket exists in primary S3 scan

**Minimum for formal path**: Hops 1, 3, and 4 must be CONFIRMED.

**Note**: This path uses EC2 and IAM dependency context to establish the entry and pivot, but the core target is an S3 bucket (primary service scope). This is valid because the bucket and its data are the primary analysis target.

**Impact**: Attacker reads, modifies, or exfiltrates data from S3 buckets accessible to the instance role. If bucket contains customer data, backups, or secrets, this is a data breach via compute compromise.

**Remediation priority**:
1. Scope IAM role S3 permissions to minimum required buckets and actions
2. Restrict EC2 instance internet exposure
3. Enable bucket logging and CloudTrail S3 data events
4. Enable versioning on target bucket

---

### AP-REF-05: Lambda Function Role to S3 Data Access (Cross-Service)

**Pattern**: Lambda Function → Execution Role → S3 Read/Write → Data Access

**Chain hops**:
1. **Lambda Function**: Function exists with an execution role that has S3 permissions (from Lambda dependency context)
2. **S3 Permissions**: Role has `s3:GetObject`, `s3:PutObject`, or broader actions on target buckets
3. **S3 Target**: Target bucket exists and is sensitive (from primary S3 scan)
4. **Function Invocation**: Function is invokable by broad principals or has public trigger

**Evidence requirements**:
- Hop 1 CONFIRMED: Lambda dependency context shows function and its role
- Hop 2 CONFIRMED: IAM dependency context shows role policy with S3 actions
- Hop 3 CONFIRMED: bucket exists in primary S3 scan
- Hop 4 CONFIRMED if Lambda function policy shows broad invoke permissions; INFERRED if invoke policy not available

**Minimum for formal path**: Hops 1, 2, and 3 must be CONFIRMED.

**Impact**: If the Lambda function can be invoked by unauthorized principals, or if the function code is compromised, attacker gains access to S3 buckets via the function's execution role.

**Remediation priority**:
1. Restrict Lambda invoke permissions
2. Scope execution role S3 permissions to minimum required
3. Enable bucket logging

---

### AP-REF-06: Website Bucket Content Injection (Supply Chain)

**Pattern**: Writable Website Bucket → Inject Malicious Content → End Users Served Malicious Content

**Chain hops**:
1. **Website Hosting**: Bucket has static website hosting enabled
2. **Write Access**: Policy allows `s3:PutObject` to broad or public principals
3. **Content Delivery**: Website content is served to end users (website endpoint active)
4. **Supply Chain Impact**: Injected JavaScript or HTML reaches end users

**Evidence requirements**:
- Hop 1 CONFIRMED: `get-bucket-website` succeeds in scan
- Hop 2 CONFIRMED: policy analysis shows write access to broad principals
- Hop 3 CONFIRMED if website configuration is present; INFERRED if unclear whether actively served
- Hop 4 INFERRED: supply chain impact depends on what content is injected

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED.

**Impact**: Attacker injects malicious JavaScript, phishing pages, or modified content into a website bucket. End users visiting the site are served attacker-controlled content — credential theft, malware delivery, or brand damage.

**Remediation priority**:
1. Remove broad write permissions immediately
2. Restrict PutObject to deployment pipelines only (specific IAM roles)
3. Enable versioning to allow rollback
4. Enable bucket logging to detect unauthorized writes

---

### AP-REF-07: Public Bucket + No Logging = Undetected Exfiltration

**Pattern**: Public/Broadly Accessible Bucket → No Logging → No CloudTrail S3 Data Events → Data Exfiltration Without Detection

**Chain hops**:
1. **Broad Access**: Bucket is publicly accessible or broadly accessible to many principals
2. **No Bucket Logging**: S3 server access logging is not enabled
3. **No CloudTrail Data Events**: CloudTrail does not capture S3 object-level events for this bucket (from CloudTrail dependency context)
4. **Undetected Access**: Exfiltration or unauthorized reads leave no audit trail

**Evidence requirements**:
- Hop 1 CONFIRMED: public access analysis shows the bucket is broadly accessible
- Hop 2 CONFIRMED: logging status in scan shows not enabled
- Hop 3 CONFIRMED if CloudTrail dependency context shows no S3 data events; INFERRED if CloudTrail context is missing
- Hop 4 INFERRED: undetected access is the consequence (standard reasoning)

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED.

**Impact**: Data exfiltration from the bucket goes undetected because no access logging captures who accessed what and when. Incident response is severely hampered.

**Remediation priority**:
1. Enable S3 server access logging immediately
2. Enable CloudTrail S3 data events for sensitive buckets
3. Fix the public access issue (enable public access block)

---

### AP-REF-08: Broad Write + No Versioning = Destructive Attack

**Pattern**: Broad Write Access → Overwrite/Delete Objects → No Versioning → Permanent Data Loss

**Chain hops**:
1. **Write Access**: Bucket policy grants `s3:PutObject` and/or `s3:DeleteObject` to broad principals (not necessarily public — could be overly broad IAM or cross-account)
2. **No Versioning**: Versioning is disabled or suspended
3. **Data Destruction**: Attacker overwrites or deletes objects permanently

**Evidence requirements**:
- Hop 1 CONFIRMED: policy analysis shows write/delete actions to broad principals
- Hop 2 CONFIRMED: versioning status in scan shows disabled/not configured
- Hop 3 INFERRED: data destruction is the consequence (standard reasoning)

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED.

**Impact**: Attacker can permanently destroy or replace data in the bucket with no recovery mechanism. Critical for backup buckets, audit logs, or production data stores.

**Remediation priority**:
1. Enable versioning immediately
2. Restrict write permissions to specific, known principals
3. Consider MFA Delete for critical buckets
4. Enable logging for forensic visibility

---

### AP-REF-09: Bucket Policy Tampering via PutBucketPolicy

**Pattern**: Broad PutBucketPolicy Access → Attacker Replaces Policy → Establishes Persistent Access

**Chain hops**:
1. **Policy Write Access**: Bucket policy grants `s3:PutBucketPolicy` to broad or unauthorized principals
2. **Policy Replacement**: Attacker replaces the bucket policy with one granting themselves full access
3. **Persistent Access**: New policy gives attacker ongoing read/write/admin access to the bucket

**Evidence requirements**:
- Hop 1 CONFIRMED: policy analysis shows `s3:PutBucketPolicy` action to broad principals
- Hop 2 INFERRED: policy replacement is the standard exploitation technique
- Hop 3 INFERRED: persistence follows from policy control

**Minimum for formal path**: Hop 1 must be CONFIRMED plus at least one additional CONFIRMED hop (e.g., no bucket-level public access block to prevent the new policy from taking effect, or no logging to detect the change).

**Note**: If only Hop 1 is CONFIRMED, keep as a CRITICAL direct finding with escalation risk noted in impact. Only elevate to formal attack path if a second hop is also confirmed.

**Impact**: Attacker who can modify the bucket policy can grant themselves persistent, stealthy access to all bucket data and operations, surviving credential rotations and IAM changes.

**Remediation priority**:
1. Remove `s3:PutBucketPolicy` from broad principals
2. Enable bucket logging to detect policy changes
3. Use SCP to restrict who can modify bucket policies

---

### AP-REF-10: Account PAB Disabled + Multiple Exposed Buckets = Account-Wide Data Risk

**Pattern**: Account-Level Public Access Block Disabled → Multiple Buckets with Public Policies/ACLs → Wide Data Exposure

**Chain hops**:
1. **Account Safety Net Missing**: Account-level public access block is disabled
2. **Multiple Bucket Exposures**: Two or more buckets have public policies or ACLs (from primary scan)
3. **Sensitive Data Spread**: At least one exposed bucket appears sensitive

**Evidence requirements**:
- Hop 1 CONFIRMED: account-level public access block status in scan
- Hop 2 CONFIRMED: multiple buckets with public policies/ACLs visible in scan
- Hop 3 CONFIRMED if sensitive bucket names/tags; INFERRED if names are ambiguous

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED.

**Impact**: Without the account-level safety net, every bucket's exposure is only as good as its individual policy. Multiple exposed buckets indicate systemic misconfiguration, not one-off mistakes. Data breach risk spans the entire account.

**Remediation priority**:
1. Enable account-level public access block immediately
2. Review and fix each individually exposed bucket
3. Audit bucket contents for sensitive data

---

### AP-REF-11: Sensitive Bucket Accessible via Overprivileged IAM Role

**Pattern**: Overprivileged IAM Role → S3 Wildcard Access → Sensitive Bucket Data

**Chain hops**:
1. **Overprivileged Role**: IAM role has `s3:*` or broad S3 actions on `Resource: *` (from IAM dependency context)
2. **Role Assumption**: Role can be assumed by broad principals or is attached to an exposed EC2 instance
3. **Sensitive Bucket**: Sensitive buckets exist in the account (from primary S3 scan)
4. **Data Access**: Attacker accesses sensitive bucket data via the overprivileged role

**Evidence requirements**:
- Hop 1 CONFIRMED: IAM dependency context shows role policy with broad S3 permissions
- Hop 2 CONFIRMED if role trust policy or EC2 attachment is visible; INFERRED if trust policy not available
- Hop 3 CONFIRMED: sensitive buckets visible in primary S3 scan
- Hop 4 INFERRED: data access follows from permissions + bucket existence

**Minimum for formal path**: Hops 1 and 3 must be CONFIRMED.

**Impact**: An overprivileged role provides a path to sensitive bucket data regardless of bucket-level controls. Even if the bucket has no public access, an IAM role with `s3:*` can read, write, or delete everything.

**Remediation priority**:
1. Scope role S3 permissions to specific buckets and actions
2. Tighten role trust policy
3. Add bucket-level denials for unexpected principals if needed

---

### AP-REF-12: CloudTrail Log Bucket Tampering

**Pattern**: Broad Access to CloudTrail Log Bucket → Delete/Overwrite Logs → Cover Attack Tracks

**Chain hops**:
1. **CloudTrail Bucket Identified**: CloudTrail dependency context identifies the log delivery bucket
2. **Write/Delete Access**: Bucket policy or IAM permissions allow `s3:DeleteObject`, `s3:PutObject`, or `s3:*` to non-CloudTrail principals
3. **Log Destruction**: Attacker deletes or overwrites CloudTrail logs to cover their tracks

**Evidence requirements**:
- Hop 1 CONFIRMED: CloudTrail dependency context shows trail configuration with S3 bucket name
- Hop 2 CONFIRMED: bucket policy (from primary scan) shows write/delete permissions for non-service principals
- Hop 3 INFERRED: log destruction is the standard exploitation intent

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED.

**Impact**: Attacker destroys or modifies audit logs, making it impossible to reconstruct the attack timeline. This is a forensic-destruction path that enables other attacks to go undetected.

**Remediation priority**:
1. Restrict bucket write/delete to CloudTrail service principal only
2. Enable versioning and MFA Delete on the log bucket
3. Enable log file validation in CloudTrail

---

## 5. Sensitive Bucket Heuristics

Use bucket names, tags, and context to tune severity. Raise concern if bucket names contain:
- `prod`, `production`, `customer`, `userdata`, `billing`, `invoice`, `finance`, `hr`, `backup`, `db`, `database`, `private`, `internal`, `audit`, `security`, `logs`, `cloudtrail`, `config`, `terraform`, `state`, `pii`, `medical`, `legal`, `secret`, `credential`, `key`

Lower concern if bucket names contain:
- `static`, `assets`, `public`, `cdn`, `website`, `www`, `media`, `images`

Do not treat name-only heuristics as proof of sensitivity, but use them to prioritize review and severity.

---

## 6. False Positive and Context Controls

### Intentional Public Content — mark as NEEDS_REVIEW or lower severity when ALL of:
- Bucket name suggests `static`, `assets`, `public`, `cdn`, or `website`
- Website hosting is enabled or object-read is clearly the intended function
- Access is limited to `s3:GetObject`
- No broad write/delete permissions exist
- No signs of sensitive content

### Service Principal Access — do NOT flag as public exposure when:
- Principal is an AWS service principal (`cloudtrail.amazonaws.com`, `logging.s3.amazonaws.com`, `delivery.logs.amazonaws.com`, etc.)
- Access is clearly tied to managed service integrations

### Condition-Restricted Policies — do NOT automatically treat as public when:
- `Principal: *` is tightly restricted by VPC endpoint (`aws:sourceVpce`), organization ID (`aws:PrincipalOrgID`), specific account/ARN conditions, or tightly scoped source IP ranges
- These may warrant `NEEDS_REVIEW` but not automatic `CRITICAL`

### ACL Neutralized by Public Access Block:
- If ACLs are public but account/bucket settings fully block or ignore them, focus on config hygiene, not real exposure

---

## 7. Dependency Context Usage Rules (S3 Specific)

### You MAY:
- Use IAM dependency context to identify roles/users with S3 permissions and validate access paths
- Use EC2 dependency context to confirm instance-to-bucket attack chains
- Use Lambda dependency context to confirm function-to-bucket access paths
- Use CloudTrail dependency context to assess monitoring coverage for S3 buckets
- Reference dependency data in `attack_paths[].chain[]` hops and remediation steps

### You MUST NOT:
- Perform a standalone IAM privilege audit from dependency context
- Emit EC2 findings (open SGs, missing encryption, etc.) as independent findings
- Emit CloudTrail findings unrelated to S3 bucket monitoring
- Treat dependency context as a full scan of that service
- Invent role names, instance IDs, function names, or trail configurations not in the input

### When dependency context is missing:
- Note in the `narrative` that cross-service attack paths could not be fully validated
- Keep the S3-direct finding and mention potential downstream risk in the finding's `impact` field
- Do NOT create formal attack paths with more than 1 unconfirmed inference

---

## 8. Attack Path Construction Workflow

Follow this order when analyzing S3 scan output:

### Step 1: Build relationship maps (Section 2)
Map all S3 buckets and their configurations. Evaluate real public exposure using the access evaluation order. Map dependency context to S3 resources.

### Step 2: Identify direct findings (Section 3)
Walk through each misconfiguration pattern against the scan data. Emit `findings[]` entries for every confirmed issue.

### Step 3: Attempt attack path matching (Section 4)
For each publicly accessible, broadly accessible, or weakly controlled bucket:
1. Check which reference attack paths (AP-REF-01 through AP-REF-12) could apply
2. For each candidate path, verify each hop against actual scan evidence
3. Label each hop as `CONFIRMED` or `INFERRED`
4. Count confirmed and inferred hops
5. If the path meets the evidence threshold (≥2 CONFIRMED, ≤1 critical unexplained inference), emit it as a formal `attack_paths[]` entry
6. If the path does NOT meet the threshold, keep relevant issues as normal findings and mention potential risk in `impact` or `narrative`

### Step 4: Cross-reference findings and paths
- Add `attack_path_ids` to any finding that participates in a formal attack path
- Ensure attack path `chain[]` references actual finding IDs

### Step 5: Rank remediation
- Prioritize fixes that break confirmed attack paths
- Prioritize public write fixes over public read fixes
- Prioritize account-level public access block (fixes many paths at once)
- Then prioritize individual bucket exposure fixes by sensitivity

### Step 6: Write narrative and quick wins
- Narrative must reference the most severe confirmed attack path by bucket name
- Quick wins must prioritize attack-path-breaking fixes over standalone findings

---

## 9. Remediation Playbooks

### Playbook: Enable Account-Level Public Access Block
1. Verify no buckets require public access (or document exceptions)
2. Enable all four flags at account level
3. Monitor for application breakage
4. For intentional public buckets, use bucket-level overrides only after confirming need

### Playbook: Fix Publicly Accessible Bucket
1. Enable bucket-level public access block
2. Remove `Principal: *` from bucket policy
3. Set ACL to private
4. Audit bucket contents for leaked credentials
5. Enable logging and versioning

### Playbook: Secure Cross-Account Access
1. Identify all cross-account principals in bucket policies
2. Add restrictive conditions (OrgID, specific role ARN, external ID)
3. Scope actions to minimum required
4. Enable logging for cross-account access monitoring

### Playbook: Protect Against Destructive Attacks
1. Enable versioning on all production and sensitive buckets
2. Enable MFA Delete on critical backup/audit buckets
3. Restrict write/delete permissions to specific principals
4. Enable logging for forensic visibility

### Playbook: Improve S3 Monitoring
1. Enable S3 server access logging on all sensitive and exposed buckets
2. Enable CloudTrail S3 data events for high-value buckets
3. Set up alerts for unusual access patterns
4. Review log retention and access controls

---

## 10. Output Guidance

### Finding output
- Mention the **actual bucket name** from the scan
- Explain whether access is **read**, **write**, **delete**, or **admin-level**
- State whether exposure is **public**, **cross-account**, or **internal but weakly controlled**
- Mention blast radius (single bucket, account-wide if PAB disabled, cross-account)
- Keep fix guidance specific and safe

### Attack path output
- `full_path_summary` must use real bucket names: `Internet → bucket-policy → customer-backups-prod → s3:GetObject`
- Each `chain[]` hop must have `evidence_status` (`CONFIRMED` or `INFERRED`)
- Each `INFERRED` hop must explain why it is inferred and what data would confirm it
- `remediation_priority` must list the shortest path to break the chain

**Good finding example**:
> Bucket `customer-backups-prod` allows `s3:GetObject` to `Principal: *` without restrictive conditions and has no bucket-level public access block. Account-level public access block is also disabled. This creates direct internet read access to a likely sensitive backup bucket.

**Bad finding example**:
> Bucket policy may be risky.

---

## 11. Minimum S3 Coverage Checklist

A thorough S3 analysis must evaluate:

### Direct S3 findings:
- [ ] Account-level public access block
- [ ] Bucket-level public access block (per bucket)
- [ ] Public bucket policies (Principal: *)
- [ ] Public ACL grants (AllUsers, AuthenticatedUsers)
- [ ] Broad write/delete permissions
- [ ] Cross-account access without tight conditions
- [ ] Default encryption configuration
- [ ] Encryption type (SSE-S3 vs SSE-KMS)
- [ ] Versioning status
- [ ] MFA Delete on critical buckets
- [ ] Logging status
- [ ] Object ownership controls
- [ ] Website hosting on non-public-intended buckets
- [ ] Replication on critical buckets
- [ ] Tagging hygiene

### Attack path evaluation (using dependency context):
- [ ] Public sensitive bucket data breach (AP-REF-01)
- [ ] Public write ransomware/injection (AP-REF-02)
- [ ] Cross-account data exfiltration (AP-REF-03)
- [ ] EC2 instance role to S3 exfiltration (AP-REF-04)
- [ ] Lambda function role to S3 access (AP-REF-05)
- [ ] Website bucket content injection (AP-REF-06)
- [ ] Public bucket undetected exfiltration (AP-REF-07)
- [ ] Broad write + no versioning destruction (AP-REF-08)
- [ ] Bucket policy tampering via PutBucketPolicy (AP-REF-09)
- [ ] Account PAB disabled + multiple exposures (AP-REF-10)
- [ ] Overprivileged IAM role to sensitive bucket (AP-REF-11)
- [ ] CloudTrail log bucket tampering (AP-REF-12)

If these are not evaluated, the S3 analysis is incomplete.
