# EC2 Security Analysis Skill

> Universal rules (input interpretation, output contract, severity modifiers, false positives, dependency boundaries, evidence thresholds) are in `common_patterns.md`. This file contains **EC2-specific** patterns only.

## Service Overview

EC2 is the primary compute attack surface in most AWS accounts. This skill detects internet exposure, credential theft paths, data exposure, privilege escalation via instance roles, lateral movement, and resource hygiene issues.

---

## 1. Scanner Commands

```text
=== PRIMARY SERVICE: EC2 ===
describe-instances, describe-security-groups, describe-volumes,
describe-snapshots, describe-images, describe-key-pairs,
describe-addresses, describe-instance-attribute (userData),
describe-instances (metadata-options)

=== DEPENDENCY CONTEXT: IAM ===
list-instance-profiles, get-role, list-attached-role-policies,
list-role-policies, get-policy-version / get-role-policy

=== DEPENDENCY CONTEXT: S3 ===
list-buckets, get-bucket-acl, get-bucket-policy, get-public-access-block

=== DEPENDENCY CONTEXT: LAMBDA ===
list-functions, get-function, get-policy

=== DEPENDENCY CONTEXT: SECRETS_MANAGER ===
list-secrets

=== DEPENDENCY CONTEXT: SSM ===
describe-instance-information
```

---

## 2. Relationship Mapping (Do This First)

### EC2 Resource Maps
- **Instance → Security Groups**: which SGs are attached to which instances/ENIs
- **Instance → Public IP**: public IPs or Elastic IPs
- **Instance → Instance Profile → IAM Role**: role chain
- **Instance → Volumes**: attached EBS volumes
- **Instance → State**: running, stopped, terminated
- **Instance → Metadata Options**: IMDSv1 (`HttpTokens=optional`) vs IMDSv2 (`HttpTokens=required`)
- **Instance → Subnet/VPC**: public or private subnet
- **Instance → Tags**: production indicators (see `common_patterns.md` Section 10)

### Dependency Maps
- **IAM Role → Policies → Permissions**: actions + resources per EC2 role
- **IAM Role → S3/Lambda/Secrets Manager/SSM/IAM**: reachable targets
- **IAM Role → Wildcard Permissions**: any `*` resource or `*` action grants

### Derived Relationships
- **Internet-Reachable Instances**: public IP + SG allows inbound from `0.0.0.0/0` or `::/0`
- **High-Value Targets**: production tags + powerful IAM roles + sensitive resource access
- **Shared SG Impact**: SGs attached to multiple instances (blast radius multiplier)

---

## 3. EC2 Misconfiguration Patterns

Each pattern produces a `findings[]` entry.

### EC2-SG-ADMIN: Admin Ports Open to Internet
| Field | Value |
|-------|-------|
| Detection | Inbound rule: `0.0.0.0/0` or `::/0` on port 22 (SSH) or 3389 (RDP) |
| Category | `network_exposure` |
| Base severity | CRITICAL |
| Fix | `aws ec2 revoke-security-group-ingress --group-id {sg-id} --protocol tcp --port {port} --cidr 0.0.0.0/0` |
| Attack path role | Entry point (Hop 1) in most EC2 attack paths |

### EC2-SG-DATA: Database/Data Ports Open to Internet
| Field | Value |
|-------|-------|
| Detection | Inbound rule: `0.0.0.0/0` or `::/0` on ports `3306, 5432, 1433, 27017, 6379, 9200, 11211, 5439, 8080, 8443, 9092, 2181` |
| Category | `network_exposure` |
| Base severity | CRITICAL |
| Fix | `aws ec2 revoke-security-group-ingress --group-id {sg-id} --protocol tcp --port {port} --cidr 0.0.0.0/0` |
| Attack path role | Entry point for direct data access chains |

### EC2-SG-ALLTRAFFIC: All Traffic from Internet
| Field | Value |
|-------|-------|
| Detection | `IpProtocol: -1` with `0.0.0.0/0` or `::/0` |
| Category | `network_exposure` |
| Base severity | CRITICAL (attached+running), MEDIUM (unattached) |
| Fix | `aws ec2 revoke-security-group-ingress --group-id {sg-id} --protocol -1 --cidr 0.0.0.0/0` |

### EC2-SG-DEFAULT: Default SG with Broad Inbound Rules
| Field | Value |
|-------|-------|
| Detection | `GroupName: default` with permissive inbound rules beyond self-referencing |
| Category | `network_exposure` |
| Base severity | HIGH |
| Fix | Remove custom inbound rules from default SG; move workloads to dedicated SGs |
| Attack path role | Blast radius amplifier for new workloads |

### EC2-IMDS-V1: IMDSv1 Allowed
| Field | Value |
|-------|-------|
| Detection | `HttpTokens = optional` |
| Category | `credential_risk` |
| Base severity | HIGH (public web + role → CRITICAL, no role → MEDIUM) |
| Fix | `aws ec2 modify-instance-metadata-options --instance-id {id} --http-tokens required --http-endpoint enabled` |
| Attack path role | Critical pivot — turns SSRF into AWS credential theft |

### EC2-PUBLIC-ROLE: Public Instance with IAM Role
| Field | Value |
|-------|-------|
| Detection | Running instance with public IP AND attached instance profile/role |
| Category | `access_control` |
| Base severity | HIGH (broad perms or IMDSv1 → CRITICAL, narrow perms → HIGH) |
| Fix | Reduce role to least privilege, isolate instance, require IMDSv2 |
| Attack path role | Pivot connecting host compromise to cloud impact |

### EC2-EBS-UNENCRYPTED: Unencrypted EBS Volume
| Field | Value |
|-------|-------|
| Detection | `Encrypted: false` |
| Category | `encryption` |
| Base severity | MEDIUM (prod/DB → HIGH, detached test → LOW) |
| Fix | Snapshot → encrypted copy → new encrypted volume → replace |

### EC2-SNAP-PUBLIC: Public Snapshot
| Field | Value |
|-------|-------|
| Detection | `createVolumePermission` includes group `all` |
| Category | `data_exposure` |
| Base severity | CRITICAL |
| Fix | `aws ec2 modify-snapshot-attribute --snapshot-id {id} --attribute createVolumePermission --operation-type remove --group-names all` |
| Attack path role | Direct data exfiltration — no host compromise needed |

### EC2-SNAP-UNENCRYPTED: Unencrypted Snapshot
| Field | Value |
|-------|-------|
| Detection | `Encrypted: false` |
| Category | `encryption` |
| Base severity | MEDIUM (raise if production source) |
| Fix | Copy snapshot with encryption enabled |

### EC2-AMI-PUBLIC: Public AMI
| Field | Value |
|-------|-------|
| Detection | `Public: true` or launch permissions include `all` |
| Category | `data_exposure` |
| Base severity | HIGH (CRITICAL if internal app stack / embedded creds) |
| Fix | `aws ec2 modify-image-attribute --image-id {id} --launch-permission "Remove=[{Group=all}]"` |

### EC2-USERDATA-SECRETS: Secrets in User Data
| Field | Value |
|-------|-------|
| Detection | User data contains hardcoded secrets, tokens, private keys, API keys |
| Category | `credential_risk` |
| Base severity | HIGH |
| Status rule | `TRUE` if clearly a secret; `NEEDS_REVIEW` if suspicious but not definitive |
| Fix | Move to Secrets Manager or SSM Parameter Store; rotate exposed values |

### EC2-KEYPAIR-ORPHANED: Orphaned Key Pair
| Field | Value |
|-------|-------|
| Detection | Key pair not used by any active instance |
| Category | `resource_hygiene` |
| Base severity | LOW |

### EC2-EIP-IDLE: Idle Elastic IP
| Field | Value |
|-------|-------|
| Detection | EIP with no instance or ENI association |
| Category | `cost` |
| Base severity | LOW |

### EC2-MONITORING-DISABLED: Detailed Monitoring Disabled
| Field | Value |
|-------|-------|
| Detection | Monitoring not enabled on production/important workloads |
| Category | `logging_monitoring` |
| Base severity | LOW–MEDIUM |
| Fix | `aws ec2 monitor-instances --instance-ids {id}` |

### EC2-TERMINATION-UNPROTECTED: No Termination Protection on Production
| Field | Value |
|-------|-------|
| Detection | Production-tagged instance lacks API termination protection |
| Category | `resource_hygiene` |
| Base severity | LOW |
| Fix | `aws ec2 modify-instance-attribute --instance-id {id} --disable-api-termination` |

### EC2-STOPPED-STALE: Stopped Instance >30 Days
| Field | Value |
|-------|-------|
| Detection | `State: stopped`, transition timestamp >30 days |
| Category | `cost` |
| Base severity | MEDIUM |
| Fix | Snapshot volumes then terminate, or create AMI |

### EC2-SG-EGRESS-UNRESTRICTED: Unrestricted Outbound on Sensitive Instance
| Field | Value |
|-------|-------|
| Detection | Outbound `IpProtocol: -1`, `0.0.0.0/0` on instance with sensitive role/prod tags |
| Category | `network_exposure` |
| Base severity | MEDIUM (HIGH if powerful IAM role) |
| Fix | Restrict outbound to required destinations |

---

## 4. EC2 Attack Path Catalog

Reference paths to match against scan evidence. Emit as formal `attack_paths[]` only when evidence threshold is met (see `common_patterns.md` Section 14).

### AP-REF-01: SSRF Credential Theft via IMDSv1
**Category**: `credential_access` + `network_entry`
**Chain**: Internet → Public Web Instance (80/443) → IMDSv1 → IAM Role Creds → AWS Service Access
| Hop | Evidence |
|-----|----------|
| 1. Public IP + SG allows 80/443 from internet | CONFIRMED required |
| 2. `HttpTokens=optional` | CONFIRMED required |
| 3. Instance profile attached | CONFIRMED required |
| 4. Role has permissions to S3/SecretsManager/etc. | CONFIRMED or INFERRED |

**Impact**: SSRF queries `169.254.169.254` for role credentials → access whatever role permits.
**Break chain**: (1) Enforce IMDSv2, (2) Restrict SG, (3) Scope role permissions.

### AP-REF-02: SSH/RDP to Cloud Privilege Escalation
**Category**: `network_entry` + `credential_access`
**Chain**: Internet → SSH/RDP → Host Compromise → IAM Role → AWS Service Access
| Hop | Evidence |
|-----|----------|
| 1. Public IP + SG allows 22/3389 from internet | CONFIRMED required |
| 2. Host compromise (brute force/stolen keys) | INFERRED (standard threat model) |
| 3. Instance profile/role attached | CONFIRMED required |
| 4. Role grants sensitive access | CONFIRMED or INFERRED |

**Break chain**: (1) Revoke internet SSH/RDP, (2) Use SSM Session Manager, (3) Scope role.

### AP-REF-03: Public Instance → S3 Data Exfiltration
**Category**: `data_exfiltration`
**Chain**: Internet → Public Instance → IAM Role → S3 Read/Write
| Hop | Evidence |
|-----|----------|
| 1. Public IP + open SG | CONFIRMED required |
| 2. Host compromise | INFERRED |
| 3. Role has `s3:GetObject`/`s3:PutObject`/`s3:*` | CONFIRMED required |
| 4. Target bucket exists (from S3 dependency context) | CONFIRMED or INFERRED |

**Break chain**: (1) Restrict SG, (2) Enforce IMDSv2, (3) Scope S3 permissions, (4) Enable S3 logging.

### AP-REF-04: Public Instance → Secrets Manager / SSM Parameters
**Category**: `credential_access`
**Chain**: Internet → Public Instance → IAM Role → `secretsmanager:GetSecretValue` or `ssm:GetParameter*`
| Hop | Evidence |
|-----|----------|
| 1. Public IP + open SG | CONFIRMED required |
| 2. Host compromise | INFERRED |
| 3. Role has secrets/SSM read permissions | CONFIRMED required |
| 4. Specific secrets exist (from dependency context) | CONFIRMED or INFERRED |

**Break chain**: (1) Restrict exposure, (2) Enforce IMDSv2, (3) Scope secret access, (4) Enable rotation.

### AP-REF-05: Public Instance → Lambda Invocation → Lambda Role
**Category**: `self_escalation` + `lateral_movement`
**Chain**: Internet → Public Instance → IAM Role → `lambda:InvokeFunction` → Lambda Execution Role
| Hop | Evidence |
|-----|----------|
| 1. Public IP + open SG | CONFIRMED required |
| 2. Host compromise | INFERRED |
| 3. Role has `lambda:InvokeFunction` | CONFIRMED required |
| 4. Function exists (from Lambda context) | CONFIRMED or INFERRED |
| 5. Lambda role has broader permissions | INFERRED (needs Lambda scan) |

**Break chain**: (1) Restrict exposure, (2) Remove `lambda:InvokeFunction`, (3) Scope function resources.

### AP-REF-06: Public Instance → IAM Privilege Escalation → Account Takeover
**Category**: `self_escalation`
**Chain**: Internet → Public Instance → IAM Role → IAM Write → Create Backdoor/Escalate
| Hop | Evidence |
|-----|----------|
| 1. Public IP + open SG | CONFIRMED required |
| 2. Host compromise | INFERRED |
| 3. Role has IAM write (`iam:CreateUser`, `iam:AttachUserPolicy`, `iam:PassRole`, `iam:*`, etc.) | CONFIRMED required |
| 4. Escalation outcome | INFERRED (capability proven by Hop 3) |

**Impact**: Instance compromise → full account control. Highest-severity chain.
**Break chain**: (1) Remove IAM write from EC2 role immediately, (2) Restrict exposure, (3) Add SCP guardrails.

### AP-REF-07: Public Snapshot → Offline Data Theft
**Category**: `data_exfiltration`
**Chain**: Public Snapshot → Copy to Attacker Account → Mount and Extract
| Hop | Evidence |
|-----|----------|
| 1. Snapshot is public (`createVolumePermission: all`) | CONFIRMED required |
| 2. Snapshot is unencrypted | CONFIRMED required |
| 3. Source volume is prod/sensitive | CONFIRMED or INFERRED |

**Note**: No host compromise required. Any AWS user worldwide can copy.
**Break chain**: (1) Remove public sharing, (2) Encrypt, (3) Rotate credentials on volume.

### AP-REF-08: Public AMI → Internal Stack Exposure
**Category**: `data_exfiltration`
**Chain**: Public AMI → Clone → Extract Embedded Secrets
| Hop | Evidence |
|-----|----------|
| 1. AMI is public | CONFIRMED |
| 2. Contains internal app stack | INFERRED (from name/description/tags) |
| 3. Embedded credentials | INFERRED (can't inspect filesystem via CLI) |

**Note**: Typically only 1 CONFIRMED hop — keep as HIGH finding unless user data secrets provide a second confirmed hop. Mention attack risk in `impact` field.

### AP-REF-09: Lateral Movement via SSM
**Category**: `lateral_movement`
**Chain**: Compromised Instance → IAM Role → `ssm:SendCommand` → Other Instances
| Hop | Evidence |
|-----|----------|
| 1. Instance A is internet-reachable | CONFIRMED required |
| 2. Role has `ssm:SendCommand`/`ssm:StartSession` | CONFIRMED required |
| 3. Other instances are SSM-managed | CONFIRMED or INFERRED |
| 4. Command execution succeeds | INFERRED |

**Break chain**: (1) Remove SSM write from internet-facing roles, (2) Separate roles, (3) SSM resource controls.

### AP-REF-10: Default SG Cascade
**Category**: `network_entry`
**Chain**: Permissive Default SG → Auto-Attached to New Resources → Inherited Exposure
| Hop | Evidence |
|-----|----------|
| 1. Default SG has broad inbound rules | CONFIRMED required |
| 2. Default SG attached to running instances | CONFIRMED required |
| 3. Future resources inherit exposure | INFERRED |

**Break chain**: (1) Remove custom rules from default SG, (2) Migrate to dedicated SGs, (3) SCP/Config prevention.

### AP-REF-11: User Data Secrets + Public Instance
**Category**: `credential_access`
**Chain**: Internet → Public Instance → User Data Contains Secrets
| Hop | Evidence |
|-----|----------|
| 1. Public IP + open SG | CONFIRMED required |
| 2. Host compromise | INFERRED |
| 3. User data contains secrets (API keys, passwords, private keys) | CONFIRMED required |

**Break chain**: (1) Rotate all exposed secrets, (2) Move to Secrets Manager, (3) Remove from user data.

### AP-REF-12: Unrestricted Egress + Powerful Role = Exfiltration Channel
**Category**: `data_exfiltration`
**Chain**: Compromised Instance → Unrestricted Outbound → Exfiltrate via S3/External
| Hop | Evidence |
|-----|----------|
| 1. Instance is internet-reachable | CONFIRMED required |
| 2. Role has S3 write with broad scope | CONFIRMED required |
| 3. Outbound SG allows all traffic | CONFIRMED required |
| 4. Exfiltration method | INFERRED |

**Break chain**: (1) Restrict outbound SG, (2) Scope S3 write to internal buckets, (3) Enable flow logs.

---

## 5. EC2-Specific False Positives

> General false positive rules are in `common_patterns.md` Section 11. These are EC2-specific additions:

- **Port 80/443 on ALB/NLB SG** → expected for load balancers, not a finding alone
- **Port 443 on public web server** → only flag if combined with IMDSv1, broad role, or other weakness
- **Open SG on stopped instances** → lower severity, not currently reachable
- **Unattached SG** → MEDIUM max (hygiene, not active exposure)
- **Internal RFC1918 SG rules** → usually expected for app-to-db; review only if unusually broad
- **Outbound all-traffic on non-sensitive instances** → LOW at most
- **Public AMI as product/base image** → `NEEDS_REVIEW` unless proven internal/sensitive

---

## 6. Remediation Playbooks

### Restrict Internet-Exposed SGs
1. Enumerate all `0.0.0.0/0` / `::/0` inbound rules
2. Separate admin/data ports from expected web ports
3. Check attachment status and instance public IP
4. Revoke admin/data rules first
5. Replace with VPN/bastion/corporate CIDR or SSM

### Enforce IMDSv2
1. Identify instances with `HttpTokens=optional`
2. Prioritize public-facing instances with IAM roles
3. Validate app compatibility with IMDSv2
4. Enforce `--http-tokens required`

### Encrypt Volumes and Snapshots
1. Identify unencrypted prod-attached volumes
2. Snapshot → encrypted copy → new volume → replace
3. Enable EBS encryption by default for the region

### Remove Public Data Exposure
1. Remove public sharing from snapshots/AMIs immediately
2. Assess whether sensitive data was exposed
3. Rotate any credentials that may have been on the volume/AMI
4. Review creation pipeline to prevent recurrence

### Scope Instance Roles
1. Identify public instances with IAM roles
2. Map what each role can access (from dependency context)
3. Reduce to least privilege
4. Remove IAM write, S3 wildcard, Lambda invoke if not needed
5. Require IMDSv2

### Break Lateral Movement
1. Identify internet-facing instances with SSM write permissions
2. Remove SSM write from internet-facing roles
3. Separate internal vs internet-facing roles
4. Apply SSM resource-level access controls

---

## 7. Coverage Checklist

### Direct Findings
- [ ] SG: admin ports open (22, 3389)
- [ ] SG: data ports open (3306, 5432, 6379, etc.)
- [ ] SG: all-traffic exposure
- [ ] SG: default SG misuse
- [ ] IMDSv1 / metadata hardening
- [ ] Public IP + IAM role combinations
- [ ] EBS volume encryption
- [ ] Public snapshots + snapshot encryption
- [ ] Public AMIs
- [ ] User data secrets
- [ ] Key pair hygiene
- [ ] Idle EIPs
- [ ] Monitoring + termination protection (production)
- [ ] Stale stopped instances
- [ ] Unrestricted egress on sensitive instances

### Attack Paths (via dependency context)
- [ ] AP-REF-01: SSRF credential theft via IMDSv1
- [ ] AP-REF-02: SSH/RDP to cloud escalation
- [ ] AP-REF-03: S3 data exfiltration
- [ ] AP-REF-04: Secrets Manager / SSM access
- [ ] AP-REF-05: Lambda invocation escalation
- [ ] AP-REF-06: IAM privilege escalation
- [ ] AP-REF-07: Public snapshot offline theft
- [ ] AP-REF-08: Public AMI stack exposure
- [ ] AP-REF-09: Lateral movement via SSM
- [ ] AP-REF-10: Default SG cascade
- [ ] AP-REF-11: User data secrets harvest
- [ ] AP-REF-12: Unrestricted egress exfiltration
