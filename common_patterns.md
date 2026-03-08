# Common Security Patterns Skill

This skill applies to ALL services. Use these patterns alongside the service-specific skill.

---

## Tagging Hygiene
- Any resource without `Name`, `Environment`, or `Owner` tags → flag as LOW (resource_hygiene)
- Resources without `Environment` tag cannot be classified as prod/dev, which affects severity decisions
- If you see a resource with `Environment: production` that has issues, bump severity by one level

## Encryption Baseline
- Any data-at-rest without encryption → minimum MEDIUM
- Data-at-rest with sensitive-sounding names (e.g., "customer", "payment", "health", "pii") without encryption → HIGH
- Data-in-transit without TLS/SSL → HIGH
- Using older encryption (SSE-S3 instead of SSE-KMS with CMK) → LOW informational note

## Logging Baseline
- Any service with logging disabled → minimum HIGH
- Flow logs, access logs, audit trails are non-negotiable in production
- If logging is disabled AND there are other security findings, mention in the narrative that the combination means attacks could go undetected

## Least Privilege Assessment
- Any policy with `Action: *` → HIGH minimum
- Any policy with `Resource: *` → MEDIUM minimum  
- `Action: *` + `Resource: *` = effectively admin → CRITICAL if on a non-admin entity
- Inline policies are harder to audit than managed policies → flag as MEDIUM (access_control)

## Unused Resource Detection
- Resources that exist but are not attached/associated with anything → LOW-MEDIUM (cost + resource_hygiene)
- Examples: unattached EBS volumes, unused Elastic IPs, orphaned snapshots, empty security groups
- Unused resources with public exposure (e.g., public snapshot nobody uses) → escalate severity

## Cross-Account Access
- Any `Principal` referencing a different AWS account ID → NEEDS_REVIEW unless clearly expected
- Cross-account access without `Condition` restrictions → HIGH

## Region Awareness
- Resources in unusual regions (outside the primary 2-3 regions an account typically uses) → NEEDS_REVIEW
- Could indicate shadow IT or compromised credentials creating resources in obscure regions

## Age-Based Risk
- Access keys > 90 days → HIGH
- Access keys > 180 days → CRITICAL
- SSL/TLS certificates expiring within 30 days → MEDIUM
- AMIs older than 365 days → LOW (may have unpatched vulnerabilities)
- Snapshots older than 365 days with no lifecycle policy → LOW

## Pattern: Defense in Depth Gaps
When you see a resource protected by only ONE layer, note it:
- S3 bucket relying only on ACLs (no bucket policy, no public access block) → fragile
- EC2 relying only on security groups (no NACLs, no VPC flow logs) → fragile
- IAM user with MFA but no access key rotation → partial protection

Mention defense-in-depth gaps in the narrative.
