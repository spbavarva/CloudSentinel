# IAM Security Analysis Skill — Attack Path Edition

## Service Overview

IAM is the control plane for the AWS account. A serious IAM misconfiguration can bypass or neutralize nearly every other security control. Treat IAM findings based on blast radius: a root-level or organization-wide exposure is an account-compromise problem, not just an access-control issue.

This skill is designed for the **primary-service + dependency-context model** defined in CLAUDE.md. The IAM scanner Python file runs AWS CLI commands for IAM (primary) plus minimal dependency context from EC2, S3, Lambda, and other services. This skill tells CloudSentinel how to interpret all of that input and produce evidence-based findings and attack paths.

This skill should analyze IAM with four priorities:
1. **Who can authenticate**
2. **Who can gain privilege**
3. **Who can assume roles or act across accounts**
4. **Whether compromise would be visible and containable**

---

## 1. Input Layout and Interpretation

The IAM scanner Python file runs AWS CLI commands and delivers output in this structure:

```text
=== PRIMARY SERVICE: IAM ===
--- Command: get-account-summary ---
[output]
--- Command: get-account-authorization-details ---
[output]
--- Command: get-credential-report ---
[output]
--- Command: get-account-password-policy ---
[output]
--- Command: list-users ---
[output]
--- Command: list-roles ---
[output]
--- Command: list-groups ---
[output]
--- Command: list-policies (customer-managed, Scope=Local) ---
[output]
--- Command: list-mfa-devices (per console user) ---
[output]
--- Command: list-access-keys (per user) ---
[output]
--- Command: get-access-key-last-used (per key) ---
[output]
--- Command: list-attached-user-policies (per user) ---
[output]
--- Command: list-user-policies (per user) ---
[output]
--- Command: list-attached-role-policies (per role) ---
[output]
--- Command: list-role-policies (per role) ---
[output]
--- Command: get-policy-version (per significant policy) ---
[output]
--- Command: get-role-policy (per inline role policy) ---
[output]
--- Command: get-user-policy (per inline user policy) ---
[output]
--- Command: list-groups-for-user (per user) ---
[output]
--- Command: list-attached-group-policies (per group) ---
[output]
--- Command: get-role (per role — includes trust policy) ---
[output]

=== DEPENDENCY CONTEXT: EC2 ===
--- Command: describe-instances (instance profiles, public IPs, states) ---
[output]
--- Command: describe-security-groups (internet exposure) ---
[output]

=== DEPENDENCY CONTEXT: S3 ===
--- Command: list-buckets ---
[output]
--- Command: get-bucket-policy (for buckets referenced in IAM policies) ---
[output]
--- Command: get-public-access-block (for buckets referenced in IAM policies) ---
[output]

=== DEPENDENCY CONTEXT: LAMBDA ===
--- Command: list-functions (function names, roles, runtimes) ---
[output]

=== DEPENDENCY CONTEXT: SECRETS_MANAGER ===
--- Command: list-secrets ---
[output]

=== DEPENDENCY CONTEXT: STS ===
--- Command: get-caller-identity ---
[output]
```

### Input Interpretation Rules

1. **PRIMARY SERVICE: IAM** is the full audit scope. Every IAM user, role, group, and policy in this section must be analyzed.
2. **DEPENDENCY CONTEXT** sections are supporting evidence only. Use them to validate or disprove IAM-centered attack paths (e.g., can a role with `ec2:RunInstances` actually launch instances into a public subnet? Does the S3 bucket referenced in a policy actually exist?).
3. Do NOT perform a standalone EC2, S3, or Lambda audit from dependency context.
4. Do NOT emit findings for dependency services unless a dependency misconfiguration is directly required to explain an IAM-centered attack path.
5. If a dependency section is missing or empty, do not assume it is secure or insecure. State what could not be evaluated.
6. Do NOT invent resources, permissions, trust relationships, or policy statements not visible in the input.

### Output Contract Guardrails

- Return **valid JSON only**. Do not emit markdown fences or prose outside the JSON object.
- `findings[].severity` must always be one of `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.
- If evidence is ambiguous, keep the best-fit severity and set `findings[].status` to `NEEDS_REVIEW`. Never use `NEEDS_REVIEW` as a severity.
- `quick_wins[]` entries must include `finding_id`, `action`, `effort`, and `impact`.
- `attack_paths[].id` must use `AP-{NUMBER}`, and every `full_path_summary` must use real identity or policy names from the scan.

---

## 2. Relationship Mapping (Do This First)

Before generating any findings or attack paths, build these maps from the scan data:

### IAM Identity Maps
- **Users → Console Access**: which users have login profiles (console passwords)
- **Users → MFA Status**: which console users have MFA devices
- **Users → Access Keys**: key IDs, creation dates, last-used dates, active/inactive status
- **Users → Policies**: attached managed policies + inline policies + group-inherited policies
- **Users → Groups**: group memberships and each group's policies
- **Roles → Trust Policies**: who/what can assume each role (principals, services, conditions)
- **Roles → Permission Policies**: attached managed + inline policies for each role
- **Roles → Classification**: service role vs human-assumable vs workload vs break-glass vs service-linked
- **Policies → Actions/Resources**: for each significant policy, the allowed actions and resource scopes

### Privilege Escalation Maps
- **PassRole Holders**: users/roles with `iam:PassRole` + any compute creation right (`ec2:RunInstances`, `lambda:CreateFunction`, `ecs:RunTask`, `glue:CreateJob`, `cloudformation:CreateStack`)
- **Policy Version Manipulators**: users/roles with `iam:CreatePolicyVersion` + `iam:SetDefaultPolicyVersion`
- **Policy Attachers**: users/roles with `iam:AttachUserPolicy`, `iam:AttachRolePolicy`, `iam:PutUserPolicy`, `iam:PutRolePolicy`
- **Role Assumers**: users/roles with broad `sts:AssumeRole` (wildcard resource or targeting admin roles)
- **Trust Policy Editors**: users/roles with `iam:UpdateAssumeRolePolicy`
- **Secret Accessors**: users/roles with `secretsmanager:GetSecretValue` or `ssm:GetParameter*` on wildcard or sensitive resources

### Dependency Maps (from dependency context)
- **EC2 Instances Using IAM Roles**: which roles are attached to running instances, whether those instances are public
- **S3 Buckets Referenced in Policies**: whether target buckets exist, their public access status
- **Lambda Functions**: which roles are used as execution roles, which functions are invokable
- **Secrets**: which secrets exist and could be accessed by identified principals

### Derived Relationships
- **Admin-Equivalent Identities**: users/roles with `*:*`, `AdministratorAccess`, or escalation paths to admin
- **Internet-Reachable Role Users**: roles attached to public EC2 instances (from dependency context)
- **Cross-Account Trust Targets**: roles assumable from external accounts
- **Dormant Privileged Identities**: admin users with stale credentials

---

## 3. IAM Direct Findings — Misconfiguration Patterns

These are direct findings in the primary IAM service. Each pattern produces a `findings[]` entry.

### Pattern IAM-ROOT-KEYS: Root Account Has Active Access Keys
- **Detection**: `get-account-summary` indicates root access keys present
- **Category**: `credential_risk`
- **Base severity**: CRITICAL
- **Blast radius**: Account-wide
- **Impact**: Root keys bypass IAM boundaries and provide unrestricted API access. If leaked, the account is fully compromised.
- **Fix**: Delete root access keys from the root account and move automation to scoped IAM roles or users
- **Attack path role**: Ultimate target of privilege escalation chains; also a standalone critical finding

### Pattern IAM-ROOT-NO-MFA: Root Account Missing MFA
- **Detection**: Account summary or credential report indicates root MFA disabled
- **Category**: `credential_risk`
- **Base severity**: CRITICAL
- **Blast radius**: Account-wide
- **Impact**: A phished root password becomes full account compromise
- **Fix**: Enable MFA on root immediately and restrict root usage to break-glass scenarios
- **Attack path role**: Weakens the highest-privilege identity's authentication barrier

### Pattern IAM-USER-NO-MFA: Console User Without MFA
- **Detection**: User has console password/login profile but no MFA device
- **Category**: `credential_risk`
- **Base severity**: HIGH
- **Severity modifiers**:
  - User also has broad admin privileges → CRITICAL
  - User has AdministratorAccess or equivalent → CRITICAL
  - User has narrow read-only permissions → MEDIUM
- **Impact**: Password-only authentication is highly phishable and vulnerable to credential reuse
- **Fix**: Enforce MFA with a deny-unless-MFA policy and onboard user MFA devices
- **Attack path role**: Entry point for credential-based attack chains

### Pattern IAM-ADMIN-USER: AdministratorAccess on Human User
- **Detection**: Attached or inherited `AdministratorAccess` or `*:*` policy on a user identity
- **Category**: `access_control`
- **Base severity**: HIGH
- **Severity modifiers**:
  - No MFA → CRITICAL
  - Stale credentials → CRITICAL
  - Multiple overlapping admin indicators → CRITICAL
- **Impact**: One compromised user becomes total account compromise
- **Fix**: Replace with least-privilege or job-function-specific role assumption
- **Attack path role**: High-value target identity; chain terminus for escalation paths

### Pattern IAM-KEY-OLD: Old Access Key (>90 days)
- **Detection**: Key age > 90 days (calculated from creation date)
- **Category**: `credential_risk`
- **Base severity**: HIGH (>90d), CRITICAL (>180d)
- **Impact**: Long-lived keys are common leak material in source code, endpoints, laptops, CI logs, and local shells
- **Fix**: Rotate key, validate workloads, then disable and delete old key
- **Context note**: If key is on a production automation principal and recently used, still flag strongly but describe operational caution
- **Attack path role**: Durable credential that enables persistent API access

### Pattern IAM-KEY-UNUSED: Access Key Never Used
- **Detection**: Key exists, last-used data absent or null
- **Category**: `credential_risk`
- **Base severity**: LOW if recent, MEDIUM if older than 90 days, HIGH if attached to privileged identity and dormant for long periods
- **Impact**: Forgotten keys become invisible attack paths
- **Fix**: Disable first, verify no dependency, then delete
- **Attack path role**: Low-signal standalone, but amplifies risk on privileged identities

### Pattern IAM-PASSWORD-POLICY: No or Weak Password Policy
- **Detection**: No account password policy, or weak controls (short minimum length, missing complexity, no reuse prevention)
- **Category**: `access_control`
- **Base severity**: MEDIUM
- **Severity modifiers**: Raise to HIGH if many console users exist without MFA
- **Impact**: Increases password spraying and weak-password risk across all console users
- **Fix**: Update account password policy to strong defaults

### Pattern IAM-INLINE-POLICY: Inline Policies on Users or Roles
- **Detection**: Inline policies attached directly to identities
- **Category**: `access_control`
- **Base severity**: MEDIUM
- **Severity modifiers**: Raise to HIGH if inline policy contains wildcards, admin-equivalent rights, or escalation actions
- **Impact**: Inline policies are harder to centrally review, version, and govern; they often accumulate privilege drift
- **Fix**: Migrate durable permissions to reviewed customer-managed policies

### Pattern IAM-WILDCARD-ADMIN: Policy Allows Action:* on Resource:*
- **Detection**: Admin-style wildcard in a customer-managed or inline policy
- **Category**: `access_control`
- **Base severity**: HIGH
- **Severity modifiers**:
  - Attached to unaudited human user without MFA → CRITICAL
  - Attached to cross-account assumable role → CRITICAL
  - Attached to tightly governed admin role with MFA requirement → HIGH
- **Status rule**: Use `NEEDS_REVIEW` when the wildcard policy appears to belong to a documented break-glass or tightly controlled emergency admin role.
- **Impact**: Unrestricted privilege with no containment
- **Fix**: Replace with scoped policies; if true admin access is needed, prefer controlled role assumption
- **Attack path role**: Target destination for privilege escalation chains

### Pattern IAM-SENSITIVE-WILDCARD: Wildcard Resource on Sensitive Actions
- **Detection**: Sensitive actions permitted on `*` resource — `iam:PassRole`, `kms:Decrypt`, `secretsmanager:GetSecretValue`, `ssm:GetParameter*`, `sts:AssumeRole`
- **Category**: `access_control`
- **Base severity**: HIGH
- **Severity modifiers**: Raise to CRITICAL if combined with compute creation rights or admin role assumption
- **Impact**: Can expose secrets, pivot identities, or enable indirect privilege escalation
- **Fix**: Scope sensitive actions to specific resource ARNs
- **Attack path role**: Key pivot hop in escalation and lateral movement chains

### Pattern IAM-PASSROLE-COMPUTE: iam:PassRole with Compute Creation Rights
- **Detection**: Principal can pass roles AND create EC2/Lambda/ECS/Glue/Batch/CloudFormation resources
- **Category**: `access_control`
- **Base severity**: CRITICAL
- **Impact**: Attacker can launch code under a stronger role and steal credentials or perform privileged actions
- **Blast radius**: Often account-wide depending on passable roles
- **Fix**: Restrict passable roles by ARN and scope the target services/resources tightly
- **Attack path role**: Core escalation mechanism — creates new compute with chosen role

### Pattern IAM-POLICY-VERSION-ABUSE: Policy Version Manipulation
- **Detection**: Principal can `iam:CreatePolicyVersion` and `iam:SetDefaultPolicyVersion`
- **Category**: `access_control`
- **Base severity**: CRITICAL if policy is attached to stronger identities; HIGH otherwise
- **Impact**: Attacker can replace an existing policy with admin-equivalent permissions and activate it
- **Fix**: Remove version-management rights except from tightly controlled admin roles
- **Attack path role**: Silent escalation — modifies existing policy rather than creating new resources

### Pattern IAM-TRUST-WILDCARD: Trust Policy Uses Wildcard Principal
- **Detection**: Role trust policy with `Principal: *` or very broad external principal and weak/no conditions
- **Category**: `access_control`
- **Base severity**: CRITICAL
- **Impact**: Any AWS principal worldwide can assume the role
- **Fix**: Restrict trusted principals and require strong conditions
- **Attack path role**: Entry point — anyone can assume the role without authentication barriers

### Pattern IAM-CROSS-ACCOUNT: Cross-Account Trust Without Adequate Constraints
- **Detection**: Trusted principal from another AWS account with no external ID, weak conditions, or very broad trust
- **Category**: `access_control`
- **Base severity**: HIGH
- **Status rule**: Use `NEEDS_REVIEW` when cross-account trust appears intentional but the expected business boundary or trust restrictions cannot be fully validated from the scan.
- **Severity modifiers**: Raise to CRITICAL if trusted role is admin-equivalent or production-sensitive
- **Impact**: External account compromise can chain into this account
- **Fix**: Narrow trusted principals, add external ID where applicable, add org/account scoping conditions
- **Attack path role**: Cross-account entry point for lateral movement

### Pattern IAM-DORMANT-ADMIN: Dormant Privileged User
- **Detection**: Privileged user with stale console login and key use (>90 days inactive)
- **Category**: `credential_risk`
- **Base severity**: MEDIUM
- **Severity modifiers**: Raise to HIGH if no MFA or broad admin rights
- **Impact**: Old privileged identities are often overlooked and weakly monitored
- **Fix**: Disable credentials, validate owner/need, then remove or convert to controlled break-glass access
- **Attack path role**: Forgotten entry point with pre-existing high privileges

### Pattern IAM-DIRECT-PERMISSIONS: Many Users with Direct Policy Attachments
- **Detection**: Significant number of users have policies attached directly instead of via groups/roles
- **Category**: `access_control`
- **Base severity**: MEDIUM
- **Impact**: High operational drift, difficult review, inconsistent offboarding, easier privilege creep
- **Fix**: Move to group- or role-based access model

---

## 4. IAM Attack Path Reference Catalog

These are the **reference attack paths** that CloudSentinel should attempt to match against actual scan evidence. A path from this catalog may ONLY be emitted as a formal `attack_paths[]` entry if it meets the evidence threshold from CLAUDE.md:

- At least **2 CONFIRMED hops**
- No more than **1 critical unexplained inference**
- Path is specific to actual resources found in the scan

If evidence is insufficient, keep the relevant issues as normal findings and mention potential downstream risk in the `impact` field or `narrative`. Do NOT elevate to `attack_paths[]`.

---

### AP-REF-01: Console User Phishing to Account Takeover

**Pattern**: Phished Console User → No MFA → Admin Permissions → Full Account Control

**Chain hops**:
1. **Entry**: Console user has password-based login (login profile exists)
2. **Weak Auth**: User has no MFA device configured
3. **Admin Privilege**: User has `AdministratorAccess`, `*:*`, or equivalent privilege (directly or via group)
4. **Account Takeover**: Attacker has full API and console access to all services

**Evidence requirements**:
- Hop 1 CONFIRMED: login profile visible in credential report or user details
- Hop 2 CONFIRMED: no MFA device in `list-mfa-devices` output
- Hop 3 CONFIRMED: policy analysis shows admin-equivalent permissions
- Hop 4 INFERRED: account takeover is the logical outcome of admin access without MFA (standard threat model)

**Minimum for formal path**: Hops 1, 2, and 3 must all be CONFIRMED.

**Impact**: Attacker phishes or credential-stuffs the user's password, logs in without MFA, and gains unrestricted access to every AWS service and resource in the account.

**Remediation priority**:
1. Enable MFA on the user immediately
2. Remove direct admin policy attachment; move to role-based assumption with MFA requirement
3. Deploy deny-unless-MFA guardrail policy

---

### AP-REF-02: Old Access Key Leak to Persistent API Compromise

**Pattern**: Leaked Access Key → API Access → Privileged Actions → Data/Resource Access

**Chain hops**:
1. **Entry**: User has access key older than 90 days (increased leak probability over time)
2. **Active Key**: Key is in `Active` status
3. **Privilege**: User's policies grant sensitive or broad permissions
4. **Target**: Attacker uses permissions to access S3 data, secrets, or modify infrastructure

**Evidence requirements**:
- Hop 1 CONFIRMED: key creation date shows >90 days in scan
- Hop 2 CONFIRMED: key status `Active` in scan
- Hop 3 CONFIRMED: policy analysis shows broad or sensitive permissions
- Hop 4 CONFIRMED if dependency context shows reachable targets (S3 buckets, secrets); INFERRED if targets not enumerated

**Minimum for formal path**: Hops 1, 2, and 3 must be CONFIRMED.

**Impact**: Attacker who obtains the leaked key has persistent, long-lived API access to whatever the user's policies allow — potentially S3 data, secrets, IAM modifications, or infrastructure changes.

**Remediation priority**:
1. Rotate the access key immediately
2. Scope down user permissions to least privilege
3. Audit CloudTrail for unexpected API calls from the key

---

### AP-REF-03: PassRole Privilege Escalation via Compute

**Pattern**: Limited Principal → iam:PassRole + Compute Creation → Code Execution Under Stronger Role

**Chain hops**:
1. **Initial Principal**: User or role has limited direct permissions
2. **PassRole**: Principal has `iam:PassRole` permission (wildcard or targeting admin-capable roles)
3. **Compute Creation**: Principal can create EC2 instances, Lambda functions, ECS tasks, Glue jobs, or CloudFormation stacks
4. **Escalation**: New compute resource runs with the passed (stronger) role, giving the attacker elevated access

**Evidence requirements**:
- Hop 1 CONFIRMED: principal's policies are in the scan
- Hop 2 CONFIRMED: policy shows `iam:PassRole` action (note resource scope — wildcard vs specific role ARN)
- Hop 3 CONFIRMED: policy shows compute creation action (`ec2:RunInstances`, `lambda:CreateFunction`, etc.)
- Hop 4 CONFIRMED if passable role's permissions are in the scan; INFERRED if passable roles are not enumerated

**Minimum for formal path**: Hops 2 and 3 must be CONFIRMED (they are the core escalation mechanism).

**Impact**: Attacker creates a new compute resource with an admin-level role attached, then uses that compute resource to access any AWS service the passed role permits. This is one of the most common and dangerous IAM escalation patterns.

**Remediation priority**:
1. Restrict `iam:PassRole` to specific role ARNs the principal legitimately needs
2. Scope compute creation to specific resource constraints
3. Add SCP guardrails to block passing admin roles to new compute

---

### AP-REF-04: Policy Version Manipulation Escalation

**Pattern**: Limited Principal → CreatePolicyVersion + SetDefaultPolicyVersion → Inject Admin Policy

**Chain hops**:
1. **Initial Principal**: User or role with limited direct permissions
2. **Policy Version Create**: Principal has `iam:CreatePolicyVersion`
3. **Policy Activation**: Principal has `iam:SetDefaultPolicyVersion`
4. **Target Policy**: The policy being modified is attached to a higher-privilege identity

**Evidence requirements**:
- Hop 2 CONFIRMED: policy shows `iam:CreatePolicyVersion`
- Hop 3 CONFIRMED: policy shows `iam:SetDefaultPolicyVersion`
- Hop 4 CONFIRMED if the target policy and its attachments are visible in scan; INFERRED if resource scope is wildcard

**Minimum for formal path**: Hops 2 and 3 must be CONFIRMED.

**Impact**: Attacker silently replaces the content of an existing managed policy with admin-equivalent permissions. Any identity attached to that policy instantly gains those permissions. This is particularly dangerous because it modifies existing resources rather than creating new ones, making it harder to detect.

**Remediation priority**:
1. Remove `iam:CreatePolicyVersion` and `iam:SetDefaultPolicyVersion` from non-admin principals
2. Use SCPs to restrict policy modification actions
3. Monitor CloudTrail for `CreatePolicyVersion` events

---

### AP-REF-05: Wildcard AssumeRole to Admin Role Lateral Movement

**Pattern**: Limited Principal → sts:AssumeRole (wildcard) → Admin-Equivalent Role → Account Control

**Chain hops**:
1. **Initial Principal**: User or role with `sts:AssumeRole` on wildcard resource or broad role targets
2. **Target Role**: An admin-equivalent role exists in the account with a trust policy that allows assumption from the principal
3. **Escalation**: Attacker assumes the admin role and gains its full permissions

**Evidence requirements**:
- Hop 1 CONFIRMED: policy shows `sts:AssumeRole` with wildcard or broad resource scope
- Hop 2 CONFIRMED: admin-equivalent role exists AND its trust policy allows the principal (both visible in scan)
- Hop 3 INFERRED: escalation outcome from successful assumption (standard threat model)

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED.

**Impact**: Attacker pivots from a limited identity to an admin role, gaining full account control. The trust policy is the key enabler — if it allows the principal, the path is valid.

**Remediation priority**:
1. Scope `sts:AssumeRole` to specific role ARNs
2. Tighten trust policies on admin roles to require MFA or specific conditions
3. Separate admin roles from general-purpose roles

---

### AP-REF-06: Cross-Account Trust Chain

**Pattern**: External Account → Assume Cross-Account Role → Access Internal Resources

**Chain hops**:
1. **Entry**: Role trust policy allows a principal from another AWS account
2. **Weak Trust**: No external ID, no MFA condition, or overly broad principal specification
3. **Role Permissions**: The cross-account role has meaningful permissions on internal resources
4. **Internal Access**: External attacker accesses S3, EC2, secrets, or other internal resources

**Evidence requirements**:
- Hop 1 CONFIRMED: trust policy shows external account ID in principal
- Hop 2 CONFIRMED: conditions analysis shows missing external ID or overly broad trust
- Hop 3 CONFIRMED: role permission policies show meaningful actions/resources
- Hop 4 CONFIRMED if dependency context shows target resources exist; INFERRED if not enumerated

**Minimum for formal path**: Hops 1, 2, and 3 must be CONFIRMED.

**Impact**: If the external account is compromised, attackers can assume into this account and access whatever the role permits. Without external ID or MFA conditions, the trust is easier to abuse.

**Remediation priority**:
1. Add external ID conditions to cross-account trust policies
2. Scope trusted principals to specific role ARNs, not account roots
3. Reduce cross-account role permissions to minimum required

---

### AP-REF-07: Wildcard Trust to World-Assumable Role

**Pattern**: Any AWS Principal → Assume Wildcard-Trust Role → Role Permissions

**Chain hops**:
1. **Entry**: Role trust policy has `Principal: *` without restrictive conditions
2. **Assumption**: Any authenticated AWS principal worldwide can assume the role
3. **Privilege**: Role has meaningful permissions

**Evidence requirements**:
- Hop 1 CONFIRMED: trust policy shows `"Principal": "*"` or `"AWS": "*"` with no/weak conditions
- Hop 2 INFERRED: assumption capability is the logical consequence (standard threat model)
- Hop 3 CONFIRMED: role permission policies show meaningful actions

**Minimum for formal path**: Hops 1 and 3 must be CONFIRMED.

**Impact**: Any AWS user in any account worldwide can assume this role and gain its permissions. This is effectively public access to whatever the role can do.

**Remediation priority**:
1. Restrict trust policy to specific accounts and principals immediately
2. Add conditions (MFA, source IP, org ID) if broad trust is operationally required
3. Review and reduce role permissions

---

### AP-REF-08: Dormant Admin Credential Reactivation

**Pattern**: Stale Admin User → Credential Still Active → Reuse/Phish → Account Takeover

**Chain hops**:
1. **Target**: Privileged user has been dormant (no recent console login or key usage)
2. **Active Credentials**: Console password or access key is still active despite dormancy
3. **Admin Privilege**: User has admin-equivalent permissions
4. **Takeover**: Attacker obtains stale credentials through phishing, credential stuffing, or key discovery

**Evidence requirements**:
- Hop 1 CONFIRMED: last activity timestamps in credential report show >90 days dormancy
- Hop 2 CONFIRMED: credentials are in `Active` status
- Hop 3 CONFIRMED: policy analysis shows admin-equivalent permissions
- Hop 4 INFERRED: credential compromise is the standard threat model for dormant accounts

**Minimum for formal path**: Hops 1, 2, and 3 must be CONFIRMED.

**Impact**: Forgotten admin accounts are prime targets because they are unlikely to be monitored. An attacker who obtains the credentials has full admin access with minimal detection risk.

**Remediation priority**:
1. Disable the dormant user's credentials immediately
2. Verify with account owner whether the user is still needed
3. If retained, enforce MFA and reduce to minimum privilege

---

### AP-REF-09: Secret Access from Compromised Identity to Lateral Movement

**Pattern**: Compromised Identity → secretsmanager:GetSecretValue / ssm:GetParameter → Database/Service Credentials → Lateral Access

**Chain hops**:
1. **Compromised Identity**: User or role is compromisable (old key, no MFA, public instance attachment)
2. **Secret Access**: Identity has `secretsmanager:GetSecretValue` or `ssm:GetParameter*` on wildcard or sensitive resources
3. **Secret Content**: Secrets contain database passwords, API keys, or service credentials
4. **Lateral Access**: Attacker uses retrieved credentials to access databases, external services, or other accounts

**Evidence requirements**:
- Hop 1 CONFIRMED: identity compromise vector is confirmed (old key, no MFA on console user, or role on public instance from EC2 dependency context)
- Hop 2 CONFIRMED: policy shows secret access actions
- Hop 3 CONFIRMED if Secrets Manager dependency context lists secret names; INFERRED if wildcard resource
- Hop 4 INFERRED: lateral access depends on secret content (cannot inspect secret values from IAM scan)

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED.

**Impact**: Attacker retrieves production database passwords, API keys, or service tokens from Secrets Manager or SSM Parameter Store, enabling access to systems and data beyond what the IAM role itself permits.

**Remediation priority**:
1. Fix the identity compromise vector (rotate key, enable MFA, restrict instance exposure)
2. Scope secret access to specific secret ARNs
3. Enable secret rotation
4. Monitor CloudTrail for `GetSecretValue` and `GetParameter` events

---

### AP-REF-10: Policy Attachment Escalation

**Pattern**: Limited Principal → iam:AttachUserPolicy / iam:PutUserPolicy → Self-Elevate to Admin

**Chain hops**:
1. **Initial Principal**: User or role with limited direct permissions
2. **Policy Attachment**: Principal has `iam:AttachUserPolicy`, `iam:AttachRolePolicy`, `iam:PutUserPolicy`, or `iam:PutRolePolicy`
3. **Self-Elevation**: Attacker attaches `AdministratorAccess` or creates an inline admin policy on themselves or their role
4. **Account Control**: Principal now has unrestricted permissions

**Evidence requirements**:
- Hop 2 CONFIRMED: policy shows policy attachment actions
- Hop 3 INFERRED: self-elevation is the logical exploitation (standard escalation technique)
- Hop 4 INFERRED: account control follows from admin permissions

**Minimum for formal path**: Hop 2 must be CONFIRMED plus at least one additional CONFIRMED hop (e.g., the principal's existing policy scope showing limited permissions confirms the escalation value).

**Note**: This path may only have 1 clearly CONFIRMED hop (the policy attachment action). If so, keep as a CRITICAL direct finding with escalation risk noted in impact. Only elevate to formal attack path if a second hop (such as the principal's current limited scope or the availability of admin policies) is also CONFIRMED.

**Impact**: Attacker self-elevates from limited permissions to full admin by attaching a permissive policy to their own identity.

**Remediation priority**:
1. Remove policy attachment permissions from non-admin principals
2. Use SCPs to restrict who can attach admin policies
3. Monitor CloudTrail for `AttachUserPolicy` and `PutUserPolicy` events

---

### AP-REF-11: EC2 Instance Role to Account Escalation (Cross-Service)

**Pattern**: Public EC2 Instance → IAM Role → IAM Write Permissions → Account Takeover

**Chain hops**:
1. **Entry**: EC2 instance is internet-reachable (from EC2 dependency context: public IP + open SG)
2. **Host Compromise**: Attacker gains instance access
3. **IAM Role**: Instance has an attached role with IAM write permissions (`iam:CreateUser`, `iam:AttachUserPolicy`, `iam:CreateAccessKey`, etc.)
4. **Account Escalation**: Attacker creates backdoor users or attaches admin policies

**Evidence requirements**:
- Hop 1 CONFIRMED: EC2 dependency context shows public IP + open SG on instance
- Hop 2 INFERRED: standard assumption from internet exposure
- Hop 3 CONFIRMED: role's permission policy shows IAM write actions (visible in primary IAM scan)
- Hop 4 INFERRED: escalation outcome from IAM write access

**Minimum for formal path**: Hops 1 and 3 must be CONFIRMED.

**Note**: This path uses EC2 dependency context as the entry point but the core finding is the IAM role permissions (primary service scope). This is valid because the IAM role and its permissions are the primary analysis target.

**Impact**: Internet-facing compute resource provides the initial foothold, and the IAM role's write permissions enable full account takeover.

**Remediation priority**:
1. Remove IAM write permissions from the EC2 instance role
2. Restrict instance internet exposure (revoke SG rules)
3. Enforce IMDSv2 on the instance

---

### AP-REF-12: Weak Password Policy + Mass Console Users = Credential Attack Surface

**Pattern**: Weak Password Policy → Many Console Users → No MFA → High Probability Credential Compromise

**Chain hops**:
1. **Weak Policy**: Account password policy is missing, has short minimum length, or lacks complexity requirements
2. **Large Surface**: Multiple console users exist (quantifiable from scan)
3. **Missing MFA**: Some or all console users lack MFA
4. **Credential Compromise**: Password spraying, credential stuffing, or phishing succeeds against at least one user

**Evidence requirements**:
- Hop 1 CONFIRMED: password policy output shows weak or missing configuration
- Hop 2 CONFIRMED: user enumeration shows multiple console users
- Hop 3 CONFIRMED: MFA device listing shows users without MFA
- Hop 4 INFERRED: credential compromise probability increases with weak policy + many users + no MFA (standard threat model)

**Minimum for formal path**: Hops 1, 2, and 3 must be CONFIRMED.

**Impact**: A weak password policy combined with many MFA-less console users creates a high-probability credential compromise surface. The impact depends on the privileges of the vulnerable users — if any are admin-equivalent, this becomes an account-takeover path.

**Remediation priority**:
1. Enforce MFA on all console users
2. Strengthen password policy (minimum 14 chars, complexity, reuse prevention)
3. Deploy deny-unless-MFA guardrail policy

---

## 5. False Positive and Context Controls

### Treat as NEEDS_REVIEW (not automatic findings) when:
- One tightly controlled break-glass admin user with MFA, strong naming, and no stale keys
- An externally assumable role clearly belongs to a vetted third-party integration with narrow trust
- A CI/CD principal has long-lived credentials but is clearly isolated and recently rotated
- A role looks broad because it is service-linked or infrastructure deployment role with limited, expected trust

### Do NOT flag as MFA issues:
- Workload roles
- Service roles
- Programmatic-only identities without console access

### Lower severity when:
- The risky identity is disabled or clearly inactive
- The broad policy is attached only to a tightly governed admin role with strong assumption controls and MFA requirement

### Raise severity when:
- Production or sensitive tags indicate business-critical systems
- The identity can reach secrets, KMS, S3 backups, IAM, Organizations, or security tooling
- There are multiple overlapping compromise paths on the same identity
- Dependency context confirms the identity's permissions reach real, sensitive resources

---

## 6. Dependency Context Usage Rules (IAM Specific)

### You MAY:
- Use EC2 dependency context to identify which IAM roles are attached to public instances (entry point confirmation)
- Use S3 dependency context to confirm target buckets exist for data exfiltration paths
- Use Lambda dependency context to confirm invocable functions for escalation paths
- Use Secrets Manager dependency context to confirm accessible secrets for lateral movement paths
- Reference dependency data in `attack_paths[].chain[]` hops and remediation steps

### You MUST NOT:
- Perform a standalone EC2 security audit from dependency context
- Emit EC2 findings (open SGs, missing encryption, etc.) as independent findings
- Treat dependency context as a full scan of that service
- Assume missing dependency context means the service is secure or insecure
- Invent instance IDs, bucket names, function names, or secret names not in the input

### When dependency context is missing:
- Note in the `narrative` that cross-service attack paths could not be fully validated
- Keep the IAM-direct finding and mention potential downstream risk in the finding's `impact` field
- Do NOT create formal attack paths with more than 1 unconfirmed inference

---

## 7. Attack Path Construction Workflow

Follow this order when analyzing IAM scan output:

### Step 1: Build relationship maps (Section 2)
Map all IAM identities, their policies, their trust relationships, and their privilege escalation paths. Map dependency context to IAM identities.

### Step 2: Identify direct findings (Section 3)
Walk through each misconfiguration pattern against the scan data. Emit `findings[]` entries for every confirmed issue.

### Step 3: Attempt attack path matching (Section 4)
For each compromisable identity (console user without MFA, old access key, public instance role, wildcard-trust role):
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
- Within attack paths, prioritize fixes that neutralize the entry point or the escalation mechanism
- Then prioritize fixes that reduce blast radius

### Step 6: Write narrative and quick wins
- Narrative must reference the most severe confirmed attack path by identity name
- Quick wins must prioritize attack-path-breaking fixes over standalone findings

---

## 8. Operational Classification Rules

Classify identities where possible to inform severity and remediation:
- **Human user** → prioritize MFA, console posture, admin rights
- **Automation user** → prioritize key age, scope, role migration opportunities
- **Workload role** → prioritize trust policy, pass-role interactions, secret access
- **Break-glass admin** → acceptable only with tight controls, MFA, and rare use
- **Service-linked role** → usually not a finding unless trust or attached permissions are unexpectedly changed

---

## 9. Remediation Playbooks

### Playbook: Enforce MFA for Console Users
1. Identify all console-enabled human users
2. Roll out a deny-unless-MFA guardrail for non-self-service actions
3. Notify owners and enroll MFA devices
4. Verify after rollout and disable non-compliant users if needed

### Playbook: Remove Long-Lived Access Keys
1. Create replacement auth method if needed (prefer IAM role, then scoped fresh key)
2. Update workloads and validate
3. Set old key inactive
4. Monitor for breakage
5. Delete old key

### Playbook: Contain Privilege Escalation Paths
1. Search for `iam:PassRole`, `sts:AssumeRole`, policy version management, and attach/put policy rights
2. Restrict to approved admin automation only
3. Scope passable roles by ARN and service
4. Block broad assumption paths in trust policies

### Playbook: Migrate to Role-Based Access
1. Remove direct user policies where possible
2. Create job-function roles or groups
3. Move humans to role assumption for elevated access
4. Keep break-glass access minimal and audited

### Playbook: Secure Cross-Account Trust
1. Identify all roles with external trust principals
2. Add external ID conditions where applicable
3. Scope trusted principals to specific role ARNs
4. Reduce cross-account role permissions to minimum
5. Monitor CloudTrail for `AssumeRole` from external accounts

---

## 10. Output Guidance

### Finding output
- Mention the **real user, role, group, or policy names** from the scan
- Explain whether the risk is authentication, authorization, privilege escalation, or cross-account trust
- Describe blast radius clearly (single identity, account-wide, cross-account)
- Avoid generic "least privilege" wording without naming the exact risky capability
- Prefer `NEEDS_REVIEW` over overclaiming when trust relationships may be legitimate

### Attack path output
- `full_path_summary` must use real identity names: `user:dev-admin → iam:PassRole → lambda:CreateFunction → admin-lambda-role → *:*`
- Each `chain[]` hop must have `evidence_status` (`CONFIRMED` or `INFERRED`)
- Each `INFERRED` hop must explain why it is inferred and what data would confirm it
- `remediation_priority` must list the shortest path to break the chain

**Good finding example**:
> User `dev-admin` has `iam:PassRole` on `Resource: *` and `lambda:CreateFunction` permission. This allows creating a Lambda function with any role in the account attached, including `admin-deploy-role` which has `AdministratorAccess`. This is a privilege escalation path from a limited developer to full account admin.

**Bad finding example**:
> This user has excessive permissions and should be reviewed.

---

## 11. Minimum IAM Coverage Checklist

A thorough IAM analysis must evaluate:

### Direct IAM findings:
- [ ] Root account access keys
- [ ] Root account MFA
- [ ] Console users without MFA
- [ ] AdministratorAccess on human users
- [ ] Old access keys (>90 days)
- [ ] Unused access keys
- [ ] Password policy strength
- [ ] Inline policies with broad permissions
- [ ] Wildcard admin policies (`*:*`)
- [ ] Sensitive actions on wildcard resources
- [ ] PassRole + compute creation combinations
- [ ] Policy version manipulation capabilities
- [ ] Wildcard trust policies
- [ ] Cross-account trust without constraints
- [ ] Dormant privileged users
- [ ] Direct user policy attachments (instead of groups/roles)

### Attack path evaluation (using dependency context):
- [ ] Console phishing to account takeover (AP-REF-01)
- [ ] Old key leak to API compromise (AP-REF-02)
- [ ] PassRole privilege escalation via compute (AP-REF-03)
- [ ] Policy version manipulation escalation (AP-REF-04)
- [ ] Wildcard AssumeRole lateral movement (AP-REF-05)
- [ ] Cross-account trust chain (AP-REF-06)
- [ ] Wildcard trust world-assumable role (AP-REF-07)
- [ ] Dormant admin credential reactivation (AP-REF-08)
- [ ] Secret access to lateral movement (AP-REF-09)
- [ ] Policy attachment self-elevation (AP-REF-10)
- [ ] EC2 instance role to account escalation (AP-REF-11)
- [ ] Weak password + mass console users (AP-REF-12)

If these are not evaluated, the IAM analysis is incomplete.
