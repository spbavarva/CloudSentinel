# EC2 Security Analysis Skill — Attack Path Edition

## Service Overview

EC2 is the primary compute attack surface in most AWS accounts. This skill drives CloudSentinel's EC2 analysis — detecting internet exposure, credential theft paths, data exposure, privilege escalation via instance roles, lateral movement, and resource hygiene issues.

This skill is designed for the **primary-service + dependency-context model** defined in CLAUDE.md. The EC2 scanner Python file runs AWS CLI commands for EC2 (primary) plus minimal dependency context from IAM, S3, Lambda, and other services. This skill tells CloudSentinel how to interpret all of that input and produce evidence-based findings and attack paths.

---

## 1. Input Layout and Interpretation

The EC2 scanner Python file runs AWS CLI commands and delivers output in this structure:

```text
=== PRIMARY SERVICE: EC2 ===
--- Command: describe-instances ---
[output]
--- Command: describe-security-groups ---
[output]
--- Command: describe-volumes ---
[output]
--- Command: describe-snapshots ---
[output]
--- Command: describe-images ---
[output]
--- Command: describe-key-pairs ---
[output]
--- Command: describe-addresses ---
[output]
--- Command: describe-instance-attribute (userData) ---
[output]
--- Command: describe-instances (metadata-options) ---
[output]

=== DEPENDENCY CONTEXT: IAM ===
--- Command: list-instance-profiles ---
[output]
--- Command: get-role (per attached role) ---
[output]
--- Command: list-attached-role-policies (per attached role) ---
[output]
--- Command: list-role-policies (per attached role) ---
[output]
--- Command: get-policy-version / get-role-policy (per significant policy) ---
[output]

=== DEPENDENCY CONTEXT: S3 ===
--- Command: list-buckets ---
[output]
--- Command: get-bucket-acl (for buckets referenced in IAM policies) ---
[output]
--- Command: get-bucket-policy (for buckets referenced in IAM policies) ---
[output]
--- Command: get-public-access-block (for buckets referenced in IAM policies) ---
[output]

=== DEPENDENCY CONTEXT: LAMBDA ===
--- Command: list-functions ---
[output]
--- Command: get-function (for functions invokable by EC2 roles) ---
[output]
--- Command: get-policy (for functions invokable by EC2 roles) ---
[output]

=== DEPENDENCY CONTEXT: SECRETS_MANAGER ===
--- Command: list-secrets ---
[output]

=== DEPENDENCY CONTEXT: SSM ===
--- Command: describe-instance-information ---
[output]
```

### Input Interpretation Rules

1. **PRIMARY SERVICE: EC2** is the full audit scope. Every EC2 resource in this section must be analyzed.
2. **DEPENDENCY CONTEXT** sections are supporting evidence only. Use them to validate or disprove EC2-centered attack paths.
3. Do NOT perform a standalone IAM, S3, Lambda, or Secrets Manager audit from dependency context.
4. Do NOT emit findings for dependency services unless a dependency misconfiguration is directly required to explain an EC2-centered attack path.
5. If a dependency section is missing or empty, do not assume it is secure or insecure. State what could not be evaluated.
6. Do NOT invent resources, permissions, trust relationships, or policy statements not visible in the input.

### Output Contract Guardrails

- Return **valid JSON only**. Do not emit markdown fences or prose outside the JSON object.
- `findings[].severity` must always be one of `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.
- If evidence is ambiguous, keep the best-fit severity and set `findings[].status` to `NEEDS_REVIEW`. Never use `NEEDS_REVIEW` as a severity.
- `quick_wins[]` entries must include `finding_id`, `action`, `effort`, and `impact`.
- `attack_paths[].id` must use `AP-{NUMBER}`, and every `full_path_summary` must use real resource IDs or names from the scan.

---

## 2. Relationship Mapping (Do This First)

Before generating any findings or attack paths, build these maps from the scan data:

### EC2 Resource Maps
- **Instance → Security Groups**: which SGs are attached to which instances or ENIs
- **Instance → Public IP**: which instances have public IPs (or Elastic IPs)
- **Instance → Instance Profile → IAM Role**: which instances have roles and what those roles are named
- **Instance → Volumes**: which EBS volumes are attached to which instances
- **Instance → State**: running, stopped, terminated
- **Instance → Metadata Options**: IMDSv1 (`HttpTokens=optional`) vs IMDSv2 (`HttpTokens=required`)
- **Instance → Subnet/VPC**: whether the instance is in a public or private subnet
- **Instance → Tags**: production indicators (`prod`, `production`, `live`, `payment`, `api`, `db`, `auth`, `customer`)

### Dependency Maps (from dependency context)
- **IAM Role → Policies → Permissions**: what each attached EC2 role can do (actions + resources)
- **IAM Role → S3 Buckets**: which S3 buckets the role can read/write/list
- **IAM Role → Lambda Functions**: which Lambda functions the role can invoke
- **IAM Role → Secrets Manager**: which secrets the role can read
- **IAM Role → SSM**: whether the role has SSM access for lateral movement
- **IAM Role → IAM**: whether the role has IAM write permissions (privilege escalation)
- **IAM Role → Wildcard Permissions**: any `*` resource or `*` action grants

### Derived Relationships
- **Internet-Reachable Instances**: public IP + SG allows inbound from `0.0.0.0/0` or `::/0`
- **High-Value Targets**: instances with production tags, powerful IAM roles, or access to sensitive resources
- **Shared SG Impact**: security groups attached to multiple instances (blast radius multiplier)

A finding on an attached, running, public, production instance with a powerful role is categorically different from the same finding on an unattached SG or a stopped dev instance.

---

## 3. EC2 Direct Findings — Misconfiguration Patterns

These are direct findings in the primary EC2 service. Each pattern produces a `findings[]` entry.

### Pattern EC2-SG-ADMIN: Security Group Open to 0.0.0.0/0 on Admin Ports
- **Detection**: Inbound rule with `CidrIp` `0.0.0.0/0` or `::/0` and `FromPort`/`ToPort` covering port 22 (SSH) or 3389 (RDP)
- **Category**: `network_exposure`
- **Base severity**: CRITICAL
- **Severity modifiers**:
  - Attached to running instance with public IP → CRITICAL
  - Attached to stopped instance or instance without public IP → HIGH
  - Unattached SG → MEDIUM
- **Impact**: Direct internet access to admin protocols enables brute force, exploit attempts, stolen key reuse, and remote foothold
- **Fix**: `aws ec2 revoke-security-group-ingress --group-id {sg-id} --protocol tcp --port {port} --cidr 0.0.0.0/0`
- **Fix note**: Replace with corporate CIDR, VPN range, bastion-only rule, or use SSM Session Manager
- **Attack path role**: Common entry point (Hop 1) in most EC2 attack paths

### Pattern EC2-SG-DATA: Security Group Open to 0.0.0.0/0 on Database/Data Ports
- **Detection**: Inbound rule with `CidrIp` `0.0.0.0/0` or `::/0` and port in `[3306, 5432, 1433, 27017, 6379, 9200, 11211, 5439, 8080, 8443, 9092, 2181]`
- **Category**: `network_exposure`
- **Base severity**: CRITICAL
- **Severity modifiers**:
  - Attached to running instance with public IP → CRITICAL
  - No public IP but SG on internet-facing ENI path → HIGH
  - Unattached SG → MEDIUM
- **Impact**: Databases, caches, message brokers, and internal services become directly reachable from the internet
- **Fix**: `aws ec2 revoke-security-group-ingress --group-id {sg-id} --protocol tcp --port {port} --cidr 0.0.0.0/0`
- **Attack path role**: Entry point for direct data access chains

### Pattern EC2-SG-ALLTRAFFIC: Security Group Allows All Traffic from Internet
- **Detection**: `IpProtocol` `-1` with `0.0.0.0/0` or `::/0`
- **Category**: `network_exposure`
- **Base severity**: CRITICAL if attached to running instance; MEDIUM if unattached
- **Impact**: Every port and protocol on attached instances is exposed, maximizing remote attack surface
- **Fix**: `aws ec2 revoke-security-group-ingress --group-id {sg-id} --protocol -1 --cidr 0.0.0.0/0`
- **Attack path role**: Entry point that enables multiple attack vectors simultaneously

### Pattern EC2-SG-DEFAULT: Default Security Group with Broad Inbound Rules
- **Detection**: SG with `GroupName` `default` has non-empty permissive inbound rules beyond self-referencing
- **Category**: `network_exposure`
- **Base severity**: HIGH
- **Severity modifiers**: If the default SG is attached to running instances, raise based on exposed ports
- **Impact**: New resources auto-associated with the default SG inherit risky exposure
- **Fix**: Remove custom inbound rules from default SG and move workloads to dedicated SGs
- **Attack path role**: Amplifies blast radius of other entry points

### Pattern EC2-IMDS-V1: IMDSv1 Allowed (HttpTokens=optional)
- **Detection**: Metadata options show `HttpTokens` = `optional`
- **Category**: `credential_risk`
- **Base severity**: HIGH
- **Severity modifiers**:
  - Public web-facing instance + IAM role attached → CRITICAL
  - No IAM role attached → MEDIUM
  - Internal-only instance with role → HIGH
- **Impact**: SSRF or local code execution can retrieve instance role credentials from the metadata service
- **Fix**: `aws ec2 modify-instance-metadata-options --instance-id {instance-id} --http-tokens required --http-endpoint enabled`
- **Attack path role**: Critical pivot hop — turns web vulnerabilities into AWS credential theft

### Pattern EC2-PUBLIC-ROLE: Public Instance with Attached IAM Role
- **Detection**: Running instance has public IP AND attached instance profile/role
- **Category**: `access_control`
- **Base severity**: HIGH
- **Severity modifiers**:
  - Role has broad permissions (`*` actions or `*` resources) → CRITICAL
  - Role combined with IMDSv1 → CRITICAL
  - Role has narrow, scoped permissions → HIGH
- **Impact**: Host compromise becomes cloud compromise — attacker pivots into S3, Secrets Manager, IAM, or other AWS services
- **Fix**: Review and reduce the role to least privilege, isolate the instance, require IMDSv2
- **Attack path role**: Pivot hop that connects host-level compromise to cloud-level impact

### Pattern EC2-EBS-UNENCRYPTED: Unencrypted EBS Volume
- **Detection**: `Encrypted: false` on an EBS volume
- **Category**: `encryption`
- **Base severity**: MEDIUM
- **Severity modifiers**:
  - Attached to production, database, or customer-data instance → HIGH
  - Detached empty/test volume → LOW
- **Impact**: Data at rest is not cryptographically protected; snapshot theft or backup leakage exposes plaintext data
- **Fix**: Snapshot → encrypted copy → new encrypted volume → replace original. Cannot encrypt in-place.
- **Attack path role**: Amplifies impact of snapshot exposure chains

### Pattern EC2-SNAP-PUBLIC: Public Snapshot
- **Detection**: Snapshot attribute `createVolumePermission` includes group `all`
- **Category**: `data_exposure`
- **Base severity**: CRITICAL
- **Impact**: Any AWS account can copy the snapshot and inspect its data offline — databases, filesystem contents, SSH keys, tokens, proprietary code
- **Fix**: `aws ec2 modify-snapshot-attribute --snapshot-id {snapshot-id} --attribute createVolumePermission --operation-type remove --group-names all`
- **Attack path role**: Direct data exfiltration endpoint — no host compromise needed

### Pattern EC2-SNAP-UNENCRYPTED: Unencrypted Snapshot
- **Detection**: Snapshot has `Encrypted: false`
- **Category**: `encryption`
- **Base severity**: MEDIUM
- **Severity modifiers**: Raise if source volume appears sensitive or production
- **Fix**: Copy snapshot with encryption enabled
- **Attack path role**: Amplifies public snapshot risk

### Pattern EC2-AMI-PUBLIC: Public AMI
- **Detection**: AMI `Public: true` or launch permissions include `all`
- **Category**: `data_exposure`
- **Base severity**: HIGH
- **Severity modifiers**: Raise to CRITICAL if AMI appears to contain internal application stack, agents, or embedded credentials
- **Fix**: `aws ec2 modify-image-attribute --image-id {ami-id} --launch-permission "Remove=[{Group=all}]"`
- **Attack path role**: Exposes internal software stack and potential embedded secrets

### Pattern EC2-USERDATA-SECRETS: Secrets in User Data
- **Detection**: User data contains hardcoded secrets, tokens, private keys, API keys, or long-lived credentials
- **Category**: `credential_risk`
- **Base severity**: HIGH
- **Status rule**: Use `TRUE` when the user data clearly contains a secret or credential. Use `NEEDS_REVIEW` when the content is suspicious but not definitive from the scan evidence alone.
- **Impact**: Secrets in user data are exposed to operators, backups, AMIs, or any compromise path
- **Fix**: Move secrets to Secrets Manager or SSM Parameter Store, rotate exposed values
- **Attack path role**: Direct credential harvesting during host compromise or image reuse

### Pattern EC2-KEYPAIR-ORPHANED: Orphaned Key Pair
- **Detection**: Key pair exists but is not used by any active instance
- **Category**: `resource_hygiene`
- **Base severity**: LOW
- **Fix**: Rotate or delete unused key pairs after validation

### Pattern EC2-EIP-IDLE: Idle Elastic IP
- **Detection**: Elastic IP exists with no instance or ENI association
- **Category**: `cost`
- **Base severity**: LOW
- **Fix**: Release unused EIP if not reserved intentionally

### Pattern EC2-MONITORING-DISABLED: Detailed Monitoring Disabled on Critical Instance
- **Detection**: Instance monitoring state not enabled on production/important workloads
- **Category**: `logging_monitoring`
- **Base severity**: LOW to MEDIUM depending on workload criticality
- **Fix**: `aws ec2 monitor-instances --instance-ids {instance-id}`

### Pattern EC2-TERMINATION-UNPROTECTED: Termination Protection Disabled on Production Instance
- **Detection**: Production-tagged instance lacks API termination protection
- **Category**: `resource_hygiene`
- **Base severity**: LOW
- **Fix**: `aws ec2 modify-instance-attribute --instance-id {instance-id} --disable-api-termination`

### Pattern EC2-STOPPED-STALE: Stopped Instance Running Longer Than 30 Days
- **Detection**: `State: stopped` and `StateTransitionReason` timestamp older than 30 days
- **Category**: `cost`
- **Base severity**: MEDIUM (cost/hygiene)
- **Fix**: Snapshot attached volumes then terminate the instance, or create an AMI for future use

### Pattern EC2-SG-EGRESS-UNRESTRICTED: Unrestricted Outbound Access on Sensitive Instance
- **Detection**: Outbound rule allows all traffic (`IpProtocol: -1`, `0.0.0.0/0`) on an instance with sensitive role or production tags
- **Category**: `network_exposure`
- **Base severity**: MEDIUM
- **Severity modifiers**: Raise to HIGH if instance has powerful IAM role (data exfiltration channel)
- **Impact**: Compromised instance can exfiltrate data to any external endpoint without restriction
- **Fix**: Restrict outbound to required destinations and ports only

---

## 4. EC2 Attack Path Reference Catalog

These are the **reference attack paths** that CloudSentinel should attempt to match against actual scan evidence. A path from this catalog may ONLY be emitted as a formal `attack_paths[]` entry if it meets the evidence threshold from CLAUDE.md:

- At least **2 CONFIRMED hops**
- No more than **1 critical unexplained inference**
- Path is specific to actual resources found in the scan

If evidence is insufficient, keep the relevant issues as normal findings and mention potential downstream risk in the `impact` field or `narrative`. Do NOT elevate to `attack_paths[]`.

---

### AP-REF-01: SSRF Credential Theft via IMDSv1

**Pattern**: Internet → Public Web Instance → IMDSv1 Credential Theft → AWS Service Access

**Chain hops**:
1. **Entry**: Instance has public IP + SG allows inbound HTTP/HTTPS (80/443) from `0.0.0.0/0`
2. **Pivot**: Instance has `HttpTokens=optional` (IMDSv1 enabled)
3. **Credential Theft**: Instance has IAM role attached via instance profile
4. **Target**: IAM role has permissions to access S3, Secrets Manager, Lambda, or other AWS services

**Evidence requirements**:
- Hop 1 CONFIRMED: public IP exists AND SG rule allows 80/443 from internet (both must be in scan)
- Hop 2 CONFIRMED: metadata options show `HttpTokens=optional` in scan output
- Hop 3 CONFIRMED: instance profile attachment visible in scan output
- Hop 4 CONFIRMED if dependency context shows specific policy actions/resources; INFERRED if role exists but policy details are missing

**Minimum for formal path**: Hops 1, 2, and 3 must all be CONFIRMED. Hop 4 may be INFERRED if role exists but policy is not in dependency context.

**Impact**: Attacker exploits SSRF in web application to query `http://169.254.169.254/latest/meta-data/iam/security-credentials/{role-name}`, obtains temporary AWS credentials, and accesses whatever the role permits.

**Remediation priority**:
1. Enforce IMDSv2 (`--http-tokens required`) — breaks the credential theft pivot
2. Restrict SG inbound to expected sources where possible
3. Reduce IAM role permissions to least privilege

---

### AP-REF-02: SSH/RDP Brute Force to Cloud Privilege Escalation

**Pattern**: Internet → SSH/RDP → Host Compromise → IAM Role → AWS Service Access

**Chain hops**:
1. **Entry**: Instance has public IP + SG allows port 22 or 3389 from `0.0.0.0/0`
2. **Host Compromise**: Attacker gains shell/desktop access (via brute force, stolen keys, or exploits)
3. **Credential Theft**: Instance has IAM role attached via instance profile
4. **Target**: IAM role grants access to sensitive AWS resources

**Evidence requirements**:
- Hop 1 CONFIRMED: public IP + SG rule for 22/3389 from `0.0.0.0/0`
- Hop 2 INFERRED: host compromise is assumed if SSH/RDP is internet-exposed (standard threat model)
- Hop 3 CONFIRMED: instance profile/role attachment visible in scan
- Hop 4 CONFIRMED if dependency context shows policy details; INFERRED if role exists but policy is missing

**Minimum for formal path**: Hops 1 and 3 must be CONFIRMED. Hop 2 is always INFERRED (acceptable as the single allowed inference). Hop 4 may be CONFIRMED or INFERRED.

**Impact**: Attacker obtains interactive shell on instance, queries instance metadata or AWS CLI for credentials, and pivots to cloud services.

**Remediation priority**:
1. Revoke internet SG rule for SSH/RDP — breaks the entry point
2. Use SSM Session Manager instead of direct SSH
3. Reduce IAM role scope

---

### AP-REF-03: Public Instance to S3 Data Exfiltration

**Pattern**: Internet → Public Instance → IAM Role → S3 Bucket Read/Write

**Chain hops**:
1. **Entry**: Instance is internet-reachable (public IP + SG allows inbound from `0.0.0.0/0` on any exploitable port)
2. **Host Compromise**: Attacker gains access to the instance
3. **IAM Role**: Instance has attached role with `s3:GetObject`, `s3:PutObject`, `s3:ListBucket`, or `s3:*` permissions
4. **S3 Target**: Policy targets specific bucket(s) or uses wildcard `*`

**Evidence requirements**:
- Hop 1 CONFIRMED: public IP + open SG rule in scan
- Hop 2 INFERRED: standard assumption from internet exposure
- Hop 3 CONFIRMED: role policy in dependency context shows S3 permissions with specific actions
- Hop 4 CONFIRMED if bucket name(s) are in the policy resource field AND S3 dependency context confirms bucket exists; INFERRED if policy uses wildcard `*` resource

**Minimum for formal path**: Hops 1 and 3 must be CONFIRMED.

**Impact**: Attacker reads, modifies, or exfiltrates data from S3 buckets accessible to the instance role. If the bucket contains customer data, PII, backups, or application secrets, this is a direct data breach path.

**Remediation priority**:
1. Restrict SG inbound rules
2. Enforce IMDSv2
3. Scope S3 permissions to minimum required buckets and actions
4. Enable S3 bucket logging and CloudTrail data events

---

### AP-REF-04: Public Instance to Secrets Manager / SSM Parameter Store

**Pattern**: Internet → Public Instance → IAM Role → Secrets Manager or SSM Parameter Store

**Chain hops**:
1. **Entry**: Instance is internet-reachable
2. **Host Compromise**: Attacker gains access to the instance
3. **IAM Role**: Instance role has `secretsmanager:GetSecretValue`, `ssm:GetParameter`, or `ssm:GetParametersByPath`
4. **Secret Target**: Policy targets specific secret(s)/parameter(s) or uses wildcard

**Evidence requirements**:
- Hop 1 CONFIRMED: public IP + open SG rule
- Hop 2 INFERRED: standard assumption
- Hop 3 CONFIRMED: role policy in dependency context shows the relevant action
- Hop 4 CONFIRMED if specific secret ARN is in policy resource AND Secrets Manager dependency context lists the secret; INFERRED if wildcard resource

**Minimum for formal path**: Hops 1 and 3 must be CONFIRMED.

**Impact**: Attacker retrieves database passwords, API keys, certificates, or other secrets stored in Secrets Manager or SSM Parameter Store. These often enable deeper lateral movement.

**Remediation priority**:
1. Restrict internet exposure
2. Enforce IMDSv2
3. Scope secret access to minimum required secrets
4. Enable secret rotation

---

### AP-REF-05: Public Instance to Lambda Invocation

**Pattern**: Internet → Public Instance → IAM Role → Lambda:InvokeFunction → Lambda's Own Role

**Chain hops**:
1. **Entry**: Instance is internet-reachable
2. **Host Compromise**: Attacker gains access to the instance
3. **IAM Role**: Instance role has `lambda:InvokeFunction` permission
4. **Lambda Target**: Function name(s) identifiable from policy resource or Lambda dependency context
5. **Lambda Role**: Lambda function has its own execution role with potentially different/broader permissions

**Evidence requirements**:
- Hop 1 CONFIRMED: public IP + open SG rule
- Hop 2 INFERRED: standard assumption
- Hop 3 CONFIRMED: role policy shows `lambda:InvokeFunction`
- Hop 4 CONFIRMED if function name in policy AND Lambda dependency context confirms function exists; INFERRED if wildcard
- Hop 5 INFERRED: Lambda function's own role permissions are not typically in EC2 dependency context

**Minimum for formal path**: Hops 1 and 3 must be CONFIRMED. Hops 2 and 5 are INFERRED (Hop 5 should note that Lambda's execution role permissions were not evaluated and would need a Lambda-focused scan).

**Impact**: Attacker uses the EC2 role to invoke Lambda functions, which execute with their own roles — potentially accessing resources the EC2 role cannot reach directly. This is a privilege escalation path if the Lambda role is broader.

**Remediation priority**:
1. Restrict internet exposure
2. Remove `lambda:InvokeFunction` from the EC2 role if not required
3. Apply function-level resource restrictions

---

### AP-REF-06: Public Instance to IAM Privilege Escalation

**Pattern**: Internet → Public Instance → IAM Role → IAM Write Permissions → Account Takeover

**Chain hops**:
1. **Entry**: Instance is internet-reachable
2. **Host Compromise**: Attacker gains access
3. **IAM Role**: Instance role has IAM write permissions (`iam:CreateUser`, `iam:AttachUserPolicy`, `iam:CreateAccessKey`, `iam:PutRolePolicy`, `iam:PassRole`, `sts:AssumeRole` on broad targets, or `iam:*`)
4. **Escalation**: Attacker creates backdoor users, attaches admin policies, or assumes other roles

**Evidence requirements**:
- Hop 1 CONFIRMED: public IP + open SG rule
- Hop 2 INFERRED: standard assumption
- Hop 3 CONFIRMED: role policy in dependency context shows specific IAM write actions
- Hop 4 INFERRED: escalation outcome depends on what the attacker creates, but the capability is proven by Hop 3

**Minimum for formal path**: Hops 1 and 3 must be CONFIRMED.

**Impact**: Attacker escalates from a single instance compromise to full AWS account control. This is the highest-severity chain type.

**Remediation priority**:
1. Remove IAM write permissions from the EC2 role immediately
2. Restrict internet exposure
3. Add SCP guardrails to prevent privilege escalation patterns
4. Enable CloudTrail and IAM Access Analyzer

---

### AP-REF-07: Public Snapshot Offline Data Theft

**Pattern**: Public Snapshot → Copy to Attacker Account → Mount and Extract Data

**Chain hops**:
1. **Entry**: Snapshot has `createVolumePermission` group `all` (public)
2. **Unencrypted**: Snapshot is unencrypted (`Encrypted: false`)
3. **Sensitive Source**: Source volume appears attached to production or sensitive instance

**Evidence requirements**:
- Hop 1 CONFIRMED: snapshot attribute shows public sharing in scan
- Hop 2 CONFIRMED: encryption status in scan
- Hop 3 CONFIRMED if volume attachment/instance tags are in scan; INFERRED if volume ID exists but instance details are missing

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED.

**Note**: This path does not require host compromise. Any AWS user worldwide can copy the snapshot.

**Impact**: Attacker copies the snapshot to their own account, creates a volume, mounts it, and extracts all data — databases, keys, application code, configuration files.

**Remediation priority**:
1. Remove public sharing immediately
2. Encrypt the snapshot
3. Rotate any credentials that may have been on the volume
4. Audit snapshot creation pipeline

---

### AP-REF-08: Public AMI to Internal Stack Exposure

**Pattern**: Public AMI → Clone by Attacker → Extract Embedded Secrets and Stack Details

**Chain hops**:
1. **Entry**: AMI has `Public: true` or launch permission `all`
2. **Sensitive Content**: AMI appears to contain internal application stack (inferred from naming, description, or tags)
3. **Embedded Secrets**: AMI may contain hardcoded credentials, agents, or internal tooling

**Evidence requirements**:
- Hop 1 CONFIRMED: AMI public status in scan
- Hop 2 INFERRED: based on AMI name/description/tags (cannot inspect AMI filesystem from CLI scan alone)
- Hop 3 INFERRED: credential presence cannot be confirmed without filesystem inspection

**Minimum for formal path**: Only Hop 1 is CONFIRMED. This typically does NOT meet the 2-confirmed-hop threshold unless additional evidence (e.g., user data secrets on source instance) is present.

**Handling**: Keep as a HIGH/CRITICAL direct finding (EC2-AMI-PUBLIC). Mention potential attack path in the `impact` field. Only elevate to `attack_paths[]` if a second hop can be confirmed from scan evidence.

---

### AP-REF-09: Lateral Movement via SSM and Shared Roles

**Pattern**: Compromised Instance → IAM Role → SSM:SendCommand → Other Instances

**Chain hops**:
1. **Initial Access**: Attacker has access to Instance A (via any entry point)
2. **IAM Role**: Instance A's role has `ssm:SendCommand` or `ssm:StartSession` permissions
3. **SSM Managed Targets**: Other instances are SSM-managed (visible in dependency context)
4. **Lateral Movement**: Attacker sends commands to Instance B via SSM

**Evidence requirements**:
- Hop 1 CONFIRMED: Instance A is internet-reachable (public IP + open SG)
- Hop 2 CONFIRMED: role policy shows SSM permissions
- Hop 3 CONFIRMED if SSM dependency context lists managed instances; INFERRED if SSM context is absent
- Hop 4 INFERRED: depends on SSM command execution succeeding

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED.

**Impact**: Attacker moves laterally from one instance to others in the account without needing direct network access to them.

**Remediation priority**:
1. Remove SSM write permissions from internet-facing instance roles
2. Use SSM document access controls and resource-level restrictions
3. Separate internet-facing and internal instance roles

---

### AP-REF-10: Default SG Cascade with New Workloads

**Pattern**: Permissive Default SG → Auto-Attached to New Resources → Inherited Exposure

**Chain hops**:
1. **Misconfiguration**: Default SG has broad inbound rules (not just self-referencing)
2. **Attachment**: Default SG is currently attached to running instances
3. **Cascade Risk**: New resources launched without explicit SG inherit the permissive default

**Evidence requirements**:
- Hop 1 CONFIRMED: default SG rules visible in scan
- Hop 2 CONFIRMED: SG attachment to instances visible in scan
- Hop 3 INFERRED: future resource behavior cannot be confirmed from current scan

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED.

**Impact**: Every new instance, ENI, or Lambda VPC attachment in this VPC risks inheriting internet exposure from the permissive default SG.

**Remediation priority**:
1. Remove custom inbound rules from the default SG
2. Migrate attached workloads to dedicated SGs
3. Use SCP or AWS Config rules to prevent default SG reuse

---

### AP-REF-11: User Data Secrets + Public Instance Credential Harvest

**Pattern**: Internet → Public Instance → User Data Contains Secrets → Direct Credential Access

**Chain hops**:
1. **Entry**: Instance is internet-reachable
2. **Host Compromise**: Attacker gains access to the instance
3. **Credential Harvest**: User data (base64-decoded) contains hardcoded API keys, database passwords, private keys, or tokens

**Evidence requirements**:
- Hop 1 CONFIRMED: public IP + open SG rule
- Hop 2 INFERRED: standard assumption from internet exposure
- Hop 3 CONFIRMED: user data output in scan contains identifiable secret patterns (API keys, passwords, tokens, private key headers)

**Minimum for formal path**: Hops 1 and 3 must be CONFIRMED.

**Impact**: Attacker retrieves plaintext secrets from instance user data, gaining access to external services, databases, or APIs without needing to exploit the IAM role.

**Remediation priority**:
1. Rotate all exposed secrets immediately
2. Move secrets to Secrets Manager or SSM Parameter Store
3. Remove secrets from user data and redeploy

---

### AP-REF-12: Unrestricted Egress + Powerful Role = Data Exfiltration Channel

**Pattern**: Compromised Instance → Unrestricted Outbound → Exfiltrate via S3/External

**Chain hops**:
1. **Initial Access**: Attacker has access to the instance (via any entry point)
2. **IAM Role**: Instance role has `s3:PutObject` to attacker-controlled or wildcard bucket, OR broad internet API access
3. **Unrestricted Egress**: Outbound SG allows all traffic to `0.0.0.0/0`
4. **Exfiltration**: Attacker moves data out of the account

**Evidence requirements**:
- Hop 1 CONFIRMED: instance is internet-reachable
- Hop 2 CONFIRMED: role policy shows S3 write with wildcard or broad resource scope
- Hop 3 CONFIRMED: outbound SG rule allows all traffic
- Hop 4 INFERRED: exfiltration method depends on attacker tooling

**Minimum for formal path**: Hops 1, 2, and 3 must be CONFIRMED.

**Impact**: Attacker exfiltrates sensitive data from the account to external S3 buckets or external endpoints without network-level restriction.

**Remediation priority**:
1. Restrict outbound SG to required destinations
2. Scope S3 write permissions to specific internal buckets
3. Enable VPC Flow Logs and S3 access logging

---

## 5. False Positive and Context Controls

Do **NOT** flag the following as security findings unless additional context shows real risk:

- **Port 80/443 open on SG attached to an internet-facing ALB/NLB** → expected for load balancers
- **Port 443 open on a public web server serving a legitimate application** → expected by itself; only a finding if combined with IMDSv1, broad IAM role, or other weakness
- **Open SG attached only to stopped instances** → lower severity, not currently reachable
- **Open SG that is unattached** → hygiene risk, not active exposure. Severity: MEDIUM max
- **Internal SG rules using RFC1918 space** (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) for app-to-db communication → usually expected; review only if scope is unusually broad
- **EBS encryption disabled on ephemeral non-sensitive lab disks** → still a finding, but LOW
- **Public AMI intentionally published as a product/base image** → `NEEDS_REVIEW` unless internal/sensitive context proves otherwise
- **Outbound all-traffic on non-sensitive, non-production instances** → LOW at most

Always ask: **Is this resource actually reachable, actually attached, and actually important?**

---

## 6. Severity Tuning Rules

### Raise severity when:
- Resource is attached to a running instance
- Instance has a public IP or internet-facing path
- Instance carries an IAM role (especially with broad permissions visible in dependency context)
- Tags/names imply production or sensitive function
- Multiple findings combine into a confirmed attack path
- The issue affects a shared SG (multiple instances = blast radius multiplier)
- Dependency context confirms the role can access sensitive resources (S3 customer data, Secrets Manager, IAM write)

### Lower severity when:
- SG is unattached
- Instance is stopped
- Resource is obviously lab/dev and isolated
- Finding is primarily hygiene or cost with no real exposure path
- IAM role has narrowly scoped, read-only permissions

---

## 7. Dependency Context Usage Rules (EC2 Specific)

### You MAY:
- Use IAM role/policy data to validate EC2 attack paths (determine what the instance role can access)
- Use S3 bucket data to confirm target buckets in S3 data exfiltration paths
- Use Lambda function data to confirm invocation targets in Lambda escalation paths
- Use Secrets Manager data to confirm accessible secrets in credential theft paths
- Use SSM data to confirm managed instances in lateral movement paths
- Reference dependency findings in `attack_paths[].chain[]` hops and remediation steps

### You MUST NOT:
- Perform a general IAM privilege audit of unrelated users or roles
- Emit independent IAM, S3, or Lambda findings unrelated to EC2 attack paths
- Treat dependency context as a full scan of that service
- Assume missing dependency context means the service is secure or insecure
- Invent policy statements, bucket names, function names, or secret names not in the input

### When dependency context is missing:
- Note in the `narrative` that cross-service attack paths could not be fully validated
- Keep the EC2-direct finding (e.g., "instance has IAM role attached") and mention potential downstream risk in the finding's `impact` field
- Do NOT create formal attack paths with more than 1 unconfirmed inference

---

## 8. Attack Path Construction Workflow

Follow this order when analyzing EC2 scan output:

### Step 1: Build relationship maps (Section 2)
Map all EC2 resources and their relationships. Map dependency context to EC2 resources.

### Step 2: Identify direct findings (Section 3)
Walk through each misconfiguration pattern against the scan data. Emit `findings[]` entries for every confirmed issue.

### Step 3: Attempt attack path matching (Section 4)
For each internet-reachable instance or public resource:
1. Check which reference attack paths (AP-REF-01 through AP-REF-12) could apply
2. For each candidate path, verify each hop against actual scan evidence
3. Label each hop as `CONFIRMED` or `INFERRED`
4. Count confirmed and inferred hops
5. If the path meets the evidence threshold (≥2 CONFIRMED, ≤1 critical unexplained inference), emit it as a formal `attack_paths[]` entry
6. If the path does NOT meet the threshold, keep the relevant issues as normal findings and mention potential risk in `impact` or `narrative`

### Step 4: Cross-reference findings and paths
- Add `attack_path_ids` to any finding that participates in a formal attack path
- Ensure attack path `chain[]` references actual finding IDs

### Step 5: Rank remediation
- Prioritize fixes that break confirmed attack paths
- Within attack paths, prioritize fixes that break the earliest hop (entry point)
- Then prioritize fixes that remove the key pivot (e.g., IMDSv2 enforcement)
- Then prioritize fixes that reduce blast radius (e.g., IAM role scoping)

### Step 6: Write narrative and quick wins
- Narrative must reference the most severe confirmed attack path by resource name
- Quick wins must prioritize attack-path-breaking fixes over standalone findings

---

## 9. Remediation Playbooks

### Playbook: Restrict Internet-Exposed Security Groups
1. Enumerate all inbound rules with `0.0.0.0/0` or `::/0`
2. Separate admin/data ports from expected web ports
3. Check whether the SG is attached and whether the instance is public
4. Revoke exposed admin/data rules first
5. Replace with VPN, bastion, corporate CIDR, or private-only access
6. Re-test application reachability before and after

### Playbook: Eliminate IMDSv1 Risk
1. Identify instances where `HttpTokens=optional`
2. Prioritize public-facing instances with IAM roles
3. Validate application compatibility with IMDSv2
4. Enforce `HttpTokens=required`
5. Monitor app behavior after rollout

### Playbook: Encrypt Existing Volumes and Snapshots
1. Identify unencrypted production-attached volumes first
2. Create snapshot
3. Copy snapshot with encryption enabled
4. Create encrypted volume from copied snapshot
5. Schedule controlled replacement window if needed
6. Enable EBS encryption by default for the region

### Playbook: Remove Public Backup/Data Exposure
1. Identify public snapshots and public AMIs
2. Remove public sharing immediately
3. Assess whether secrets or sensitive data were stored in them
4. Rotate any credentials found or suspected
5. Review backup/image creation pipeline to stop recurrence

### Playbook: Review and Scope Instance Roles
1. Identify public instances with IAM roles
2. Use dependency context to determine what the role can access
3. Reduce permissions to least privilege
4. Remove unused actions (especially IAM write, S3 wildcard, Lambda invoke if not needed)
5. Require IMDSv2
6. Consider moving admin access to SSM instead of SSH

### Playbook: Break Lateral Movement Paths
1. Identify instances with SSM write permissions (`ssm:SendCommand`, `ssm:StartSession`)
2. Determine if those instances are internet-facing
3. Remove SSM write from internet-facing roles
4. Use separate roles for internal vs internet-facing instances
5. Apply SSM document and resource-level access controls

---

## 10. Output Guidance

### Finding output
- Reference **real SG, instance, volume, snapshot, or AMI IDs** from the scan
- State whether the resource is attached, running, and whether the instance is public
- Mention **blast radius**: single host, shared SG affecting N instances, cross-account via public snapshot, or account-wide via IAM escalation
- Use concise impact language explaining what an attacker gets if the issue is exploited
- Prefer practical fixes over generic advice

**Good impact example**:
> Security group sg-0abc1234 allows SSH from 0.0.0.0/0 and is attached to public instance i-0def5678 running with role app-prod-role. An attacker can attempt direct shell access and, if successful, use the instance's role to read from S3 bucket customer-data-prod and retrieve secrets from Secrets Manager.

**Bad impact example**:
> This could be risky and should be reviewed.

### Attack path output
- `full_path_summary` must use real resource IDs: `Internet → sg-0abc → i-0def → app-prod-role → customer-data-prod`
- Each `chain[]` hop must have `evidence_status` (`CONFIRMED` or `INFERRED`)
- Each `INFERRED` hop must explain why it is inferred and what data would confirm it
- `remediation_priority` must list the shortest path to break the chain

---

## 11. Minimum EC2 Coverage Checklist

A thorough EC2 analysis must evaluate:

### Direct EC2 findings:
- [ ] Public SG exposure on admin ports (22, 3389)
- [ ] Public SG exposure on data ports (3306, 5432, 6379, etc.)
- [ ] All-traffic SG exposure
- [ ] Default SG misuse
- [ ] IMDSv1 / metadata hardening
- [ ] Public IP + IAM role combinations
- [ ] Volume encryption
- [ ] Public snapshots
- [ ] Snapshot encryption
- [ ] Public AMIs
- [ ] User data secrets
- [ ] Key pair hygiene
- [ ] Idle Elastic IPs
- [ ] Monitoring and termination protection on production instances
- [ ] Stale stopped instances
- [ ] Unrestricted egress on sensitive instances

### Attack path evaluation (using dependency context):
- [ ] SSRF credential theft via IMDSv1 (AP-REF-01)
- [ ] SSH/RDP to cloud escalation (AP-REF-02)
- [ ] Public instance to S3 exfiltration (AP-REF-03)
- [ ] Public instance to Secrets Manager (AP-REF-04)
- [ ] Public instance to Lambda invocation (AP-REF-05)
- [ ] Public instance to IAM privilege escalation (AP-REF-06)
- [ ] Public snapshot offline theft (AP-REF-07)
- [ ] Public AMI stack exposure (AP-REF-08)
- [ ] Lateral movement via SSM (AP-REF-09)
- [ ] Default SG cascade (AP-REF-10)
- [ ] User data secrets harvest (AP-REF-11)
- [ ] Unrestricted egress exfiltration (AP-REF-12)

If these are not evaluated, the EC2 analysis is incomplete.
