# Common Security Patterns

Cross-service patterns used alongside every service skill file. Service skills should **reference** these patterns, not redefine them.

---

## 1. Input & Output Contract (Universal)

These rules apply to **every** service scan. Service skill files must NOT restate them.

### Input Interpretation
1. `PRIMARY SERVICE` section = full audit scope. Analyze every resource.
2. `DEPENDENCY CONTEXT` sections = supporting evidence only.
3. Do NOT perform standalone audits of dependency services.
4. Do NOT emit dependency-service findings unless directly required to explain a primary-service attack path.
5. Missing/empty dependency sections are neither secure nor insecure. State what could not be evaluated.
6. Do NOT invent resources, permissions, or trust relationships not visible in the input.

### Output Contract
- Return **valid JSON only**. No markdown fences or prose outside the JSON object.
- `findings[].severity`: `CRITICAL` | `HIGH` | `MEDIUM` | `LOW`
- `findings[].status`: `TRUE` | `NEEDS_REVIEW` — never use `NEEDS_REVIEW` as a severity value.
- `quick_wins[]` entries: `finding_id`, `action`, `effort`, `impact`
- `attack_paths[].id`: `AP-{NUMBER}` format
- `full_path_summary`: real resource IDs/names from the scan in arrow notation

---

## 2. Severity Adjustment Matrix

Base severity comes from the service skill file. These **universal modifiers** always apply on top:

| Modifier | Effect | Example |
|----------|--------|---------|
| Resource is attached + running + public IP | Raise severity | Open SSH on running public instance → CRITICAL |
| Resource is stopped or no public IP | Lower one level | Open SSH on stopped instance → HIGH |
| Resource is unattached / orphaned | Cap at MEDIUM | Permissive rule on unattached SG → MEDIUM |
| Production tags present (`prod`, `production`, `live`, `payment`, `api`, `db`, `auth`, `customer`, `pci`, `pii`) | Raise one level | Unencrypted volume on prod DB → HIGH |
| Dev/test/lab/sandbox tags | Lower one level | Open port on `sandbox` instance → downgrade |
| Finding enables a confirmed attack path | Raise one level | IMDSv1 on public instance with powerful role → CRITICAL |
| Shared resource (SG on multiple instances, policy on multiple roles) | Note blast radius | Permissive SG attached to 10 instances → amplifier |
| Resource is internet-facing + no logging | Compound risk | Mention in narrative: attacks could go undetected |

---

## 3. Public Exposure Patterns

These patterns apply across all services that can be publicly accessible.

| Signal | Service Examples | Baseline Severity |
|--------|-----------------|-------------------|
| `0.0.0.0/0` or `::/0` in inbound rules | EC2 SGs, VPC NACLs | CRITICAL (admin/DB ports), HIGH (other ports) |
| `Principal: *` or `Principal: "*"` in policies | S3 bucket policy, VPC endpoint policy, IAM trust | CRITICAL if write/delete, HIGH if read-only |
| `PubliclyAccessible: true` | RDS, Redshift | CRITICAL if SG also allows internet |
| Public snapshot / public AMI | EC2/EBS snapshots, AMIs | CRITICAL (snapshot), HIGH (AMI) |
| Anonymous ACL grants (`AllUsers`, `AuthenticatedUsers`) | S3 ACLs | CRITICAL (write), HIGH (read) |
| Website hosting enabled on bucket | S3 | Raise severity if combined with sensitive data |
| `IpProtocol: -1` (all traffic) with `0.0.0.0/0` | EC2 SGs | CRITICAL if attached to running instance |

---

## 4. Encryption Patterns

| Check | Baseline Severity | Notes |
|-------|-------------------|-------|
| Data-at-rest without encryption | MEDIUM | Raise to HIGH if resource name suggests sensitive data |
| Data-at-rest with sensitive naming (`customer`, `payment`, `health`, `pii`, `secret`) without encryption | HIGH | |
| Data-in-transit without TLS/SSL | HIGH | Check ELB listeners, RDS `force_ssl`, S3 bucket policy `aws:SecureTransport` |
| SSE-S3 instead of SSE-KMS with CMK | LOW (informational) | Not a finding unless compliance requires CMK |
| KMS key disabled or pending deletion | HIGH | Resources encrypted with this key become inaccessible or unrecoverable |
| Unencrypted backups/snapshots | MEDIUM | Raise if source data is production/sensitive |
| EBS default encryption disabled (account-level) | MEDIUM | New volumes created without explicit encryption |

---

## 5. Logging & Monitoring Patterns

| Check | Baseline Severity | Notes |
|-------|-------------------|-------|
| VPC Flow Logs disabled | HIGH | Non-negotiable for production VPCs |
| S3 access logging disabled | MEDIUM | Raise to HIGH on public or sensitive buckets |
| ELB access logging disabled | HIGH | Required for internet-facing load balancers |
| RDS log exports disabled | MEDIUM | Raise to HIGH on production databases |
| CloudTrail S3 data events not enabled | MEDIUM | Raise if S3 is a confirmed attack path target |
| EC2 detailed monitoring disabled on production | LOW–MEDIUM | Based on workload criticality |
| Any logging disabled + other security findings present | Compound | Mention in narrative: "attacks could go undetected" |

---

## 6. Least Privilege & Wildcard Patterns

| Check | Baseline Severity | Notes |
|-------|-------------------|-------|
| `Action: *` + `Resource: *` | CRITICAL | Effectively admin — unless on a documented break-glass role |
| `Action: *` on specific resource | HIGH | Overprivileged but scoped |
| `Resource: *` on sensitive actions (`iam:PassRole`, `kms:Decrypt`, `secretsmanager:GetSecretValue`, `sts:AssumeRole`, `ssm:GetParameter*`) | HIGH | Raise to CRITICAL if combined with compute creation rights |
| `iam:PassRole` + compute creation (`ec2:RunInstances`, `lambda:CreateFunction`, `ecs:RunTask`, `glue:CreateJob`, `cloudformation:CreateStack`) | CRITICAL | Core privilege escalation mechanism |
| `iam:CreatePolicyVersion` + `iam:SetDefaultPolicyVersion` | CRITICAL | Silent policy escalation |
| Inline policies on users/roles | MEDIUM | Harder to audit; raise to HIGH if contains wildcards |

---

## 7. Age & Staleness Patterns

| Check | Threshold | Baseline Severity |
|-------|-----------|-------------------|
| Access key age | >90 days → HIGH, >180 days → CRITICAL | Long-lived keys are common leak material |
| Access key never used | Recent → LOW, >90 days → MEDIUM, privileged + dormant → HIGH | Forgotten keys become invisible attack paths |
| Console user last login | >90 days inactive + privileged → HIGH | Dormant admin = unmonitored entry point |
| Stopped EC2 instance | >30 days → LOW (cost/hygiene) | |
| Detached EBS volume | No recent attachment → LOW | Raise if unencrypted + contains data |
| Snapshot without lifecycle | >365 days → LOW | Raise if public or unencrypted |
| AMI age | >365 days → LOW | May contain unpatched vulnerabilities |
| SSL/TLS certificate expiry | <30 days → MEDIUM | |
| Stale VPC peering with active routes | Assess actual reachability | Raise to HIGH if routes cover sensitive subnets |

---

## 8. Cross-Account Access Patterns

| Check | Baseline Severity | Notes |
|-------|-------------------|-------|
| Trust policy allows external account without conditions | HIGH | Raise to CRITICAL if role is admin-equivalent |
| Trust policy with `Principal: *` (any AWS account) | CRITICAL | Any account worldwide can assume the role |
| Bucket policy grants to external account | HIGH | Assess scope: `s3:GetObject` vs `s3:*` |
| Snapshot/AMI shared to external account | HIGH | Data exfiltration risk |
| VPC peering to external account | MEDIUM | Raise based on reachable subnet sensitivity |
| Cross-account without ExternalId | MEDIUM | Confused deputy risk |
| Use `NEEDS_REVIEW` when cross-account trust appears intentional but constraints can't be fully validated from scan | | |

---

## 9. Unused Resource Patterns

| Check | Category | Baseline Severity |
|-------|----------|-------------------|
| Orphaned key pair (no active instance) | `resource_hygiene` | LOW |
| Idle Elastic IP (no association) | `cost` | LOW |
| Detached EBS volume | `cost` / `resource_hygiene` | LOW |
| Snapshot not linked to active workload | `resource_hygiene` | LOW |
| AMI not referenced by instances/ASGs/launch templates | `resource_hygiene` | LOW |
| Unused IGW (not attached or no subnet routes) | `resource_hygiene` | LOW |
| Unused NAT gateway (no route references) | `cost` | MEDIUM (expensive) |
| Empty security group (no instances attached) | `resource_hygiene` | LOW |
| **Exception**: Unused resource with public exposure (public snapshot nobody uses) → escalate severity | | |

---

## 10. Tagging Hygiene

| Check | Baseline Severity | Notes |
|-------|-------------------|-------|
| Missing `Name`, `Environment`, or `Owner` tag | LOW (`resource_hygiene`) | |
| Missing `Environment` tag | Affects severity classification | Cannot determine prod vs dev — note in findings |
| `Environment: production` with security issues | Raise severity one level | |

### Production Indicator Tags
These tag values signal production workloads — apply severity raise:
`prod`, `production`, `live`, `payment`, `api`, `db`, `auth`, `customer`, `critical`, `pci`, `pii`

---

## 11. False Positive Controls

Suppress or downgrade these unless combined with other findings:

| Pattern | Action | Rationale |
|---------|--------|-----------|
| Port 80/443 open on internet-facing ALB/NLB | Not a finding by itself | Expected for web traffic |
| Public web server on 443 serving legitimate app | Not a finding by itself | Expected architecture |
| Outbound all-traffic on non-sensitive instances | LOW at most | Default AWS behavior |
| Default SG with only self-referencing rules | Not a finding | AWS default, no exposure |
| Public AMI intentionally published as base image | `NEEDS_REVIEW` | Verify intent before flagging |
| Internal RFC1918 ranges in SG rules | Expected | App-to-DB communication |
| SSE-S3 encryption (vs SSE-KMS) | LOW informational only | Unless compliance mandates CMK |
| Cross-account trust with proper ExternalId + conditions | Lower severity | Properly constrained |

---

## 12. Defense in Depth

When a resource is protected by **only one layer**, note it in the narrative:

| Single-layer pattern | Better defense |
|---------------------|----------------|
| S3 bucket relies only on ACLs (no bucket policy, no public access block) | Add bucket policy + account-level public access block |
| EC2 relies only on SGs (no NACLs, no VPC flow logs) | Add NACLs for subnet-level control + enable flow logs |
| IAM user with MFA but no access key rotation | Add key rotation policy |
| RDS with SG restriction but `PubliclyAccessible: true` | Set `PubliclyAccessible: false` + private subnet |

---

## 13. Dependency Context Boundaries

Dependency context supports: chain validation, blast radius explanation, remediation prioritization.

Dependency context must **never**: become a standalone audit, generate unrelated findings, or be treated as complete scan data for that service.

**Exception**: Reference a dependency misconfiguration if directly required to explain the primary-service attack path chain.

### Service Dependency Map

| Primary Service | Useful Dependency Context |
|----------------|--------------------------|
| EC2 | IAM (instance roles, policies), S3 (exfil targets), Lambda (invokable functions), Secrets Manager, SSM |
| S3 | IAM (who can access buckets), CloudTrail (data event logging), EC2/Lambda (compute accessing S3) |
| IAM | EC2 (which roles are on public instances), S3 (do target buckets exist), Lambda, Secrets Manager, STS |
| VPC | EC2 (workload sensitivity), IAM (endpoint policies) |
| RDS | EC2/VPC (network exposure), IAM (authentication), KMS (encryption keys) |
| EBS | EC2 (which instances use volumes), IAM (snapshot sharing), KMS (encryption keys) |
| AMI | EC2 (which instances use AMIs), IAM (launch permissions) |
| ELB | EC2 (target instances), ACM (certificates), S3 (access log bucket) |

---

## 14. Attack Path Evidence Standards

These thresholds apply universally. Service skill files must NOT restate them.

| Rule | Requirement |
|------|-------------|
| Minimum confirmed hops | 2 per formal attack path |
| Maximum unexplained inferred hops | 1 per path |
| 1 confirmed + 3 inferred | Too weak — keep as normal findings |
| `CONFIRMED` | Scan directly proves the hop (SG rule, public IP, attached role, policy statement) |
| `INFERRED` | Strongly suggested but not fully proven. Must explain: why inferred + what data would confirm |
| Insufficient evidence | Keep as finding with downstream risk mentioned in `impact` or `narrative` — do NOT elevate to `attack_paths[]` |

### Remediation Prioritization
When breaking attack chains, prioritize in this order:
1. **Break the entry point** (remove public exposure, restrict SG)
2. **Remove the key pivot** (enforce IMDSv2, scope IAM role)
3. **Reduce blast radius** (encrypt data, enable logging, add monitoring)
