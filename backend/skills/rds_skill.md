# RDS Security Analysis Skill - Attack Path Edition

## Service Overview

RDS is the primary relational data surface in many AWS accounts. A weak RDS configuration can create direct internet exposure, silent data theft through snapshots, broken recoverability, or application-to-database compromise paths that bypass the expectation that databases remain private.

This skill is designed for the **primary-service + dependency-context model** defined in `AGENTS.md` / `CLAUDE.md`. The RDS scanner Python file should run AWS CLI commands for RDS (primary) plus minimal dependency context from EC2, VPC, Secrets Manager, and KMS. This skill tells CloudSentinel how to interpret that input and produce evidence-based findings and attack paths.

Primary goals:
1. Detect direct database exposure
2. Evaluate snapshot sharing and data-at-rest controls
3. Check whether subnet placement and SG rules match private-database intent
4. Assess backup, deletion-protection, and logging posture
5. Validate only evidence-backed attack paths

---

## 1. Input Layout and Interpretation

The RDS scanner Python file should run AWS CLI commands and deliver output in this structure:

```text
=== PRIMARY SERVICE: RDS ===
--- Command: describe-db-instances ---
[output]
--- Command: describe-db-clusters ---
[output]
--- Command: describe-db-subnet-groups ---
[output]
--- Command: describe-db-snapshots (manual snapshots) ---
[output]
--- Command: describe-db-cluster-snapshots (manual cluster snapshots) ---
[output]
--- Command: describe-db-snapshot-attributes (per manual snapshot) ---
[output]
--- Command: describe-db-cluster-snapshot-attributes (per manual cluster snapshot) ---
[output]
--- Command: describe-db-parameters (security-relevant parameters per DB parameter group) ---
[output]
--- Command: describe-db-cluster-parameters (security-relevant parameters per cluster parameter group) ---
[output]
--- Command: list-tags-for-resource (per DB instance / cluster / snapshot) ---
[output]
--- Command: describe-certificates ---
[output]

=== DEPENDENCY CONTEXT: EC2 ===
--- Command: describe-security-groups ---
[output]
--- Command: describe-subnets ---
[output]
--- Command: describe-route-tables ---
[output]
--- Command: describe-vpcs ---
[output]
--- Command: describe-instances (instances in the same VPCs or referenced by DB SG rules) ---
[output]

=== DEPENDENCY CONTEXT: SECRETS_MANAGER ===
--- Command: list-secrets ---
[output]
--- Command: describe-secret (per secret referenced by ManageMasterUserPassword or related tags/ARNs) ---
[output]

=== DEPENDENCY CONTEXT: KMS ===
--- Command: describe-key (per referenced KMS key) ---
[output]
```

### Input Interpretation Rules

1. **PRIMARY SERVICE: RDS** is the full audit scope. Every DB instance, cluster, subnet group, snapshot, and security-relevant parameter set in this section must be analyzed.
2. **DEPENDENCY CONTEXT** sections are supporting evidence only. Use them to validate or disprove RDS-centered attack paths.
3. Do NOT perform a standalone EC2, Secrets Manager, or KMS audit from dependency context.
4. Do NOT emit findings for dependency services unless a dependency misconfiguration is directly required to explain an RDS-centered attack path.
5. If a dependency section is missing or empty, do not assume it is secure or insecure. State what could not be evaluated.
6. Do NOT invent endpoints, credentials, SG relationships, or snapshot-sharing targets not visible in the input.

### Output Contract Guardrails

- Return **valid JSON only**. Do not emit markdown fences or prose outside the JSON object.
- `findings[].severity` must always be one of `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.
- If evidence is ambiguous, keep the best-fit severity and set `findings[].status` to `NEEDS_REVIEW`. Never use `NEEDS_REVIEW` as a severity.
- `quick_wins[]` entries must include `finding_id`, `action`, `effort`, and `impact`.
- `attack_paths[].id` must use `AP-{NUMBER}`, and every `full_path_summary` must use real DB identifiers, subnet groups, snapshot IDs, SG IDs, or instance IDs from the scan.

---

## 2. Relationship Mapping (Do This First)

Before generating any findings or attack paths, build these maps from the scan data:

### RDS Resource Maps
- **DB Instance / Cluster -> Engine and Version**: engine family, version, endpoint type
- **DB Instance / Cluster -> PubliclyAccessible**: whether the endpoint is intended to be internet-routable
- **DB Instance / Cluster -> VPC and Subnet Group**: where the database lives
- **DB Instance / Cluster -> Security Groups**: which SGs protect the endpoint
- **DB Instance / Cluster -> Encryption**: `StorageEncrypted`, `KmsKeyId`, and snapshot encryption state
- **DB Instance / Cluster -> Backup Posture**: backup retention period, automated backups where visible
- **DB Instance / Cluster -> Deletion Protection**: enabled or not
- **DB Instance / Cluster -> Log Exports**: `EnabledCloudwatchLogsExports` and engine-appropriate logging
- **DB Instance / Cluster -> Parameter Groups**: DB parameter groups and cluster parameter groups
- **DB Instance / Cluster -> Tags**: production and sensitivity indicators (`prod`, `production`, `customer`, `payments`, `auth`, `pci`, `pii`, `critical`)
- **Snapshot -> Source DB / Cluster**: which DB created the snapshot
- **Snapshot -> Sharing**: public (`all`) vs named external accounts
- **Snapshot -> Encryption**: encrypted or plaintext

### Parameter Interpretation Rules
- **PostgreSQL / Aurora PostgreSQL**: treat `rds.force_ssl=1` as strong evidence of TLS enforcement
- **MySQL / MariaDB / Aurora MySQL**: treat `require_secure_transport=ON` or equivalent enabled state as strong evidence of TLS enforcement
- **SQL Server / Oracle**: only claim TLS enforcement if a collected parameter clearly proves it
- If the engine-specific parameter is absent from the collected data, do not guess. Use `NEEDS_REVIEW` only when the remaining evidence strongly suggests the control may be missing.

### Dependency Maps (from dependency context)
- **Security Group -> Inbound Rules**: whether DB ports are reachable from `0.0.0.0/0`, `::/0`, broad private CIDRs, or specific app SGs
- **Subnet Group -> Route Intent**: whether member subnets are public, private, or mixed
- **EC2 Instances -> Same VPC / SG Reference**: which public or sensitive EC2 instances can reach the DB
- **Secrets Manager -> Master Credential Secret**: whether master secret management is visible and scoped
- **KMS Key -> Key State**: enabled, disabled, pending deletion, AWS-managed vs customer-managed

### Derived Relationships
- **Direct Internet-Reachable DB**: `PubliclyAccessible=true` + SG allows the engine port from `0.0.0.0/0` or `::/0`
- **Architecturally Misplaced DB**: DB subnet group contains IGW-routed subnets or mixed public/private intent
- **Offline Data Exposure**: public or broad snapshot sharing + snapshot copy/restore path
- **App-to-DB Pivot Path**: public EC2 instance + reachable DB SG path + sensitive DB target
- **Recovery Weakness**: short/no backups + no deletion protection on important DBs

Always distinguish between:
- **Network reachability**
- **Credential availability**
- **Data exposure through snapshots**
- **Operational resilience controls**

---

## 3. RDS Direct Findings - Misconfiguration Patterns

These are direct findings in the primary RDS service. Each pattern produces a `findings[]` entry.

### Pattern RDS-PUBLIC-ENDPOINT: Publicly Accessible Database Endpoint
- **Detection**: `PubliclyAccessible: true` on a DB instance or cluster member
- **Category**: `network_exposure`
- **Base severity**: HIGH
- **Severity modifiers**:
  - SG also allows the database/admin port from `0.0.0.0/0` or `::/0` -> CRITICAL
  - Production or sensitive tags/names -> raise one level
  - Public flag is enabled but SG is tightly restricted to fixed corporate/VPN CIDRs -> HIGH, not CRITICAL by default
- **Impact**: The database is intended to be reachable outside the private network boundary. If SG rules are weak or credentials leak, the data store is directly exposed.
- **Fix**: `aws rds modify-db-instance --db-instance-identifier {db-id} --no-publicly-accessible --apply-immediately`
- **Cluster fix**: Use `aws rds modify-db-cluster ...` or modify member instances as appropriate for the engine model
- **Attack path role**: Common entry point for direct DB access paths

### Pattern RDS-SG-INTERNET: Database Security Group Open to the Internet
- **Detection**: Attached SG allows inbound from `0.0.0.0/0` or `::/0` on engine/admin ports such as 3306, 5432, 1433, 1521, or 2484
- **Category**: `network_exposure`
- **Base severity**: CRITICAL
- **Severity modifiers**:
  - DB is publicly accessible -> CRITICAL
  - DB is not public but the SG is broad and the subnet group is mixed/public -> CRITICAL
  - DB is private and the rule only exposes broad internal RFC1918 ranges -> HIGH or `NEEDS_REVIEW` based on architecture
- **Impact**: Internet or overly broad network sources can reach the database listener directly.
- **Fix**: `aws ec2 revoke-security-group-ingress --group-id {sg-id} --protocol tcp --port {db-port} --cidr 0.0.0.0/0`
- **Attack path role**: Direct entry point for data access and brute-force or exploit attempts

### Pattern RDS-SUBNET-PUBLIC: DB Subnet Group Uses Public or Mixed-Intent Subnets
- **Detection**: Subnet group contains subnets whose route tables have `0.0.0.0/0` to an IGW, or the subnet naming/route intent is mixed
- **Category**: `network_exposure`
- **Base severity**: MEDIUM
- **Severity modifiers**:
  - DB is publicly accessible or SG is internet-open -> HIGH
  - Sensitive or production database -> HIGH
- **Impact**: The network placement does not match private-database expectations and makes accidental exposure easier.
- **Fix**: Move the DB to dedicated private subnets and update the DB subnet group
- **Attack path role**: Architectural enabler for exposure and lateral movement paths

### Pattern RDS-NO-ENCRYPTION: Storage Encryption Disabled
- **Detection**: `StorageEncrypted: false`
- **Category**: `encryption`
- **Base severity**: HIGH for production/sensitive DBs, MEDIUM otherwise
- **Impact**: Data at rest is not cryptographically protected. Snapshot theft, backup leakage, or storage misuse can expose plaintext data.
- **Fix**: RDS encryption generally cannot be enabled in place. Snapshot the DB, copy/restore to a new encrypted instance or cluster, and cut over.
- **Attack path role**: Amplifies the impact of snapshot or backup exposure

### Pattern RDS-SNAPSHOT-PUBLIC: Manual Snapshot Shared Publicly
- **Detection**: Snapshot attributes include group `all`
- **Category**: `data_exposure`
- **Base severity**: CRITICAL
- **Impact**: Any AWS account can copy or restore the snapshot and inspect its data offline.
- **Fix**: `aws rds modify-db-snapshot-attribute --db-snapshot-identifier {snapshot-id} --attribute-name restore --values-to-remove all`
- **Cluster fix**: `aws rds modify-db-cluster-snapshot-attribute --db-cluster-snapshot-identifier {snapshot-id} --attribute-name restore --values-to-remove all`
- **Attack path role**: Direct offline data theft path with no host compromise required

### Pattern RDS-SNAPSHOT-CROSS-ACCOUNT: Snapshot Shared to External Account
- **Detection**: Snapshot attributes include specific external AWS account IDs
- **Category**: `access_control`
- **Base severity**: HIGH
- **Status rule**: Use `NEEDS_REVIEW` when sharing appears to be a controlled DR or backup-account workflow and the business justification cannot be validated from the scan.
- **Severity modifiers**:
  - Sensitive or production source DB -> raise one level
  - External sharing plus no encryption -> CRITICAL
- **Impact**: Data can be restored or copied from another account outside the expected control boundary.
- **Fix**: Remove unnecessary account IDs from the snapshot restore attribute
- **Attack path role**: External data exposure path when sharing is broader than intended

### Pattern RDS-BACKUP-WEAK: Backup Retention Disabled or Too Low
- **Detection**: `BackupRetentionPeriod` is `0`, or clearly low for an important DB
- **Category**: `backup_recovery`
- **Base severity**: MEDIUM
- **Severity modifiers**:
  - Production, customer-data, auth, or financial DB -> HIGH
  - Combined with deletion protection off -> HIGH
- **Impact**: Recovery from deletion, corruption, or destructive actions is weak or impossible.
- **Fix**: `aws rds modify-db-instance --db-instance-identifier {db-id} --backup-retention-period {days} --apply-immediately`
- **Cluster fix**: `aws rds modify-db-cluster --db-cluster-identifier {cluster-id} --backup-retention-period {days} --apply-immediately`
- **Attack path role**: Increases the impact of destructive actions and ransomware-style operations

### Pattern RDS-DELETION-PROTECTION-OFF: Deletion Protection Disabled on Important Database
- **Detection**: `DeletionProtection: false`
- **Category**: `resource_hygiene`
- **Base severity**: MEDIUM
- **Severity modifiers**:
  - Production or critical data store -> HIGH
  - Dev/test DB with short lifetime -> LOW
- **Impact**: Accidental or malicious deletion is easier.
- **Fix**: `aws rds modify-db-instance --db-instance-identifier {db-id} --deletion-protection --apply-immediately`
- **Cluster fix**: `aws rds modify-db-cluster --db-cluster-identifier {cluster-id} --deletion-protection --apply-immediately`
- **Attack path role**: Supports destructive attack outcomes when backups are also weak

### Pattern RDS-NO-LOG-EXPORTS: Database Log Exports Not Enabled
- **Detection**: `EnabledCloudwatchLogsExports` is empty or missing for engines where security-relevant exports are available
- **Category**: `logging_monitoring`
- **Base severity**: MEDIUM
- **Severity modifiers**:
  - Publicly accessible or internet-open DB -> HIGH
  - Production or regulated workload -> HIGH
- **Impact**: Authentication failures, connection patterns, and suspicious activity are harder to investigate.
- **Fix**: `aws rds modify-db-instance --db-instance-identifier {db-id} --cloudwatch-logs-export-configuration EnableLogTypes=[...] --apply-immediately`
- **Attack path role**: Makes direct access or application-to-DB compromise harder to detect

### Pattern RDS-TLS-NOT-ENFORCED: Parameter Group Does Not Enforce Secure Transport
- **Detection**: Collected engine-specific parameters clearly show TLS/SSL enforcement is disabled or absent
- **Category**: `access_control`
- **Base severity**: HIGH
- **Status rule**: Use `NEEDS_REVIEW` if the engine family supports different controls and the collected parameters are incomplete.
- **Impact**: Clients may be able to connect without transport encryption, weakening credential and data-in-transit protection.
- **Fix**: Update the DB or cluster parameter group to require secure transport, then apply/reboot if needed
- **Attack path role**: Amplifies public or broad network exposure by allowing plaintext or downgraded connections

---

## 4. RDS Attack Path Reference Catalog

These are the **reference attack paths** that CloudSentinel should attempt to match against actual scan evidence. A path from this catalog may ONLY be emitted as a formal `attack_paths[]` entry if it meets the evidence threshold from `AGENTS.md` / `CLAUDE.md`:

- At least **2 CONFIRMED hops**
- No more than **1 critical unexplained inference**
- Path is specific to actual resources found in the scan

If evidence is insufficient, keep the relevant issues as normal findings and mention possible downstream impact in `impact` or `narrative`. Do NOT elevate it into `attack_paths[]`.

---

### AP-REF-01: Direct Internet Access to Public RDS

**Pattern**: Internet -> SG Open on DB Port -> Public RDS Endpoint

**Chain hops**:
1. **Entry**: SG allows the DB port from `0.0.0.0/0` or `::/0`
2. **Reachability**: DB instance or cluster member is `PubliclyAccessible=true`
3. **Target**: Sensitive or production DB identified by tags, name, or context

**Evidence requirements**:
- Hop 1 CONFIRMED: SG rule in dependency context
- Hop 2 CONFIRMED: public accessibility in primary RDS scan
- Hop 3 CONFIRMED if tags/names indicate sensitive use; INFERRED if the DB exists but business sensitivity is unclear

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED.

**Impact**: Attackers can reach the database listener directly from the internet and attempt credential attacks, protocol exploits, or direct data access if credentials are weak or exposed elsewhere.

**Remediation priority**:
1. Remove internet SG access on the DB port
2. Disable public accessibility
3. Move the DB into private subnets if placement is also weak

---

### AP-REF-02: Public RDS + No TLS Enforcement

**Pattern**: Internet -> Public RDS -> Non-Enforced Secure Transport

**Chain hops**:
1. **Network Entry**: SG allows the DB port from internet sources
2. **Public Endpoint**: DB is publicly accessible
3. **Weak Transport Control**: Parameter group shows TLS/SSL enforcement is not enabled

**Evidence requirements**:
- Hop 1 CONFIRMED: SG rule visible
- Hop 2 CONFIRMED: `PubliclyAccessible=true`
- Hop 3 CONFIRMED when collected parameters clearly show secure transport is disabled

**Minimum for formal path**: All three hops should be CONFIRMED.

**Impact**: Direct database exposure is worsened by weak transport controls, increasing the risk of plaintext or downgraded connections and weak credential handling.

**Remediation priority**:
1. Remove internet reachability first
2. Enforce TLS in the parameter group
3. Rotate any credentials exposed over weak transport if compromise is suspected

---

### AP-REF-03: Public Manual Snapshot Offline Data Theft

**Pattern**: Public Snapshot -> Copy / Restore -> Offline Database Extraction

**Chain hops**:
1. **Entry**: Manual snapshot is shared with `all`
2. **Restore Path**: Snapshot can be copied or restored outside the account
3. **Sensitive Source**: Source DB is production or sensitive

**Evidence requirements**:
- Hop 1 CONFIRMED: snapshot attribute output shows `all`
- Hop 2 CONFIRMED: public snapshot sharing itself proves the restore path
- Hop 3 CONFIRMED if tags/names or source DB mapping show sensitivity; INFERRED otherwise

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED.

**Impact**: An attacker in any AWS account can copy the snapshot and inspect the database offline without touching the running application.

**Remediation priority**:
1. Remove public snapshot sharing immediately
2. Review all snapshots from the same source DB
3. Rotate credentials or tokens that may be stored inside the data set

---

### AP-REF-04: Cross-Account Snapshot Restore Outside Intended Boundary

**Pattern**: External Account Snapshot Share -> Restore in Another Account -> Data Exposure

**Chain hops**:
1. **Share**: Manual snapshot is shared to one or more external AWS accounts
2. **Restore Path**: External account can restore or copy the snapshot
3. **Sensitive Target**: Source DB contains important data

**Evidence requirements**:
- Hop 1 CONFIRMED: external account IDs visible in snapshot attributes
- Hop 2 CONFIRMED: restore sharing on RDS snapshots directly implies restore capability
- Hop 3 CONFIRMED if source DB is clearly important; INFERRED otherwise

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED.

**Impact**: Data leaves the primary account boundary and can be restored elsewhere without further compromise.

**Remediation priority**:
1. Remove unnecessary external sharing
2. Validate DR or backup-account requirements
3. Keep only tightly scoped, encrypted shares when justified

---

### AP-REF-05: Public EC2 App Tier to Reachable RDS Pivot

**Pattern**: Internet -> Public EC2 -> Reachable RDS SG Path -> Database Target

**Chain hops**:
1. **Entry**: EC2 dependency context shows an internet-reachable instance
2. **Host Compromise**: Attacker gains a foothold on that instance
3. **DB Reachability**: DB SG allows traffic from the EC2 instance SG, subnet CIDR, or broad private CIDR that includes the instance
4. **Target**: Important DB exists behind that reachable path

**Evidence requirements**:
- Hop 1 CONFIRMED: public EC2 instance + open SG from dependency context
- Hop 2 INFERRED: host compromise is the standard attacker assumption
- Hop 3 CONFIRMED: DB SG or CIDR relationship is visible
- Hop 4 CONFIRMED if DB identity and role are visible

**Minimum for formal path**: Hops 1, 3, and 4 must be CONFIRMED.

**Impact**: A compromise in the public app tier creates a proven network path to the database tier, reducing the DB boundary to application compromise rather than direct internet access.

**Remediation priority**:
1. Remove public exposure from the EC2 entry point or tighten the EC2 SG
2. Restrict DB SGs to exact application SGs only
3. Segment public and data tiers more strongly

---

### AP-REF-06: Public Subnet Group + Public Endpoint = Architecture-Driven Exposure

**Pattern**: IGW-Routed DB Subnets -> Publicly Accessible DB -> Direct Exposure

**Chain hops**:
1. **Placement Weakness**: DB subnet group contains public or mixed-intent subnets
2. **Public Endpoint**: DB is publicly accessible
3. **Reachability**: SG permits the DB port from broad sources

**Evidence requirements**:
- Hop 1 CONFIRMED: route-table analysis proves public or mixed subnet placement
- Hop 2 CONFIRMED: public accessibility visible
- Hop 3 CONFIRMED: SG rule visible

**Minimum for formal path**: All three hops should be CONFIRMED.

**Impact**: The network architecture and endpoint configuration align to expose the database rather than protect it as a private tier.

**Remediation priority**:
1. Move the DB into private subnets
2. Disable public accessibility
3. Remove broad SG rules

---

### AP-REF-07: Public RDS + No Log Exports = Undetected Direct Access

**Pattern**: Internet-Reachable DB -> Weak Monitoring -> Direct Breach Hard to Investigate

**Chain hops**:
1. **Exposure**: DB is internet-reachable through public accessibility and SG posture
2. **Visibility Gap**: Security-relevant log exports are not enabled
3. **Target**: Important DB instance or cluster

**Evidence requirements**:
- Hop 1 CONFIRMED: direct-exposure conditions visible
- Hop 2 CONFIRMED: missing or empty log exports in primary scan
- Hop 3 CONFIRMED if DB importance is clear; INFERRED otherwise

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED.

**Impact**: Direct database access attempts and misuse are harder to investigate or detect quickly.

**Remediation priority**:
1. Break direct exposure first
2. Enable appropriate log exports
3. Ensure log retention and monitoring exist downstream

---

### AP-REF-08: Public Snapshot + No Encryption = Plaintext Offline Breach

**Pattern**: Shared Snapshot -> Plaintext Restore -> Offline Data Exposure

**Chain hops**:
1. **Snapshot Exposure**: Snapshot is public or externally shared
2. **No Encryption**: Snapshot or source storage is unencrypted
3. **Sensitive Source**: Snapshot maps to an important DB

**Evidence requirements**:
- Hop 1 CONFIRMED: sharing attributes visible
- Hop 2 CONFIRMED: encryption state visible
- Hop 3 CONFIRMED if source DB importance is visible; INFERRED otherwise

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED.

**Impact**: Data can be restored and inspected offline without encryption protections or private-account boundaries reducing exposure.

**Remediation priority**:
1. Remove public or external sharing
2. Rebuild on encrypted storage
3. Review historical snapshots created from the same source

---

### AP-REF-09: Public Cluster Writer or Reader Endpoint Exposure

**Pattern**: Internet -> Open SG -> Public Aurora / Cluster Endpoint

**Chain hops**:
1. **Entry**: SG exposes the cluster port to broad sources
2. **Public Cluster Access**: Cluster members or endpoints are publicly accessible
3. **Multi-Endpoint Impact**: Writer and reader endpoints expose the same data plane

**Evidence requirements**:
- Hop 1 CONFIRMED: SG rule visible
- Hop 2 CONFIRMED: public accessibility on cluster members or endpoint model
- Hop 3 CONFIRMED if cluster and endpoint model are visible in the scan

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED.

**Impact**: Both write and read access paths to the clustered database may be exposed, increasing blast radius across the same dataset.

**Remediation priority**:
1. Remove internet SG access
2. Make cluster members private
3. Review all exposed endpoints, not just the writer

---

### AP-REF-10: Weak Backups + No Deletion Protection = Destructive Attack Outcome

**Pattern**: Reachable or Reachable-By-App DB -> No Deletion Protection -> Poor Recovery

**Chain hops**:
1. **Reachable Target**: DB is directly exposed or reachable from a public app tier
2. **Deletion Control Missing**: deletion protection is disabled
3. **Recovery Weakness**: backups are disabled or clearly too weak

**Evidence requirements**:
- Hop 1 CONFIRMED: direct internet exposure or EC2-to-RDS path is visible
- Hop 2 CONFIRMED: deletion protection disabled
- Hop 3 CONFIRMED: backup retention is weak

**Minimum for formal path**: All three hops should be CONFIRMED.

**Impact**: A compromise can shift from data access to destructive deletion or corruption with poor recovery options.

**Remediation priority**:
1. Break the reachable path first
2. Enable deletion protection
3. Raise backup retention and validate restores

---

## 5. False Positive and Context Controls

Do **NOT** overstate the following:

- **PubliclyAccessible=true with SG limited to a narrow corporate or VPN CIDR** -> still a finding, but not automatically CRITICAL
- **Cross-account snapshot sharing to a dedicated backup or DR account** -> use `NEEDS_REVIEW` unless the evidence shows broad or unnecessary sharing
- **Read replicas, migration DBs, or temporary cutover systems** -> keep the finding, but lower severity when the lifespan and scope are clearly limited
- **Subnet-group public placement without public accessibility and without broad SG rules** -> architecture weakness, not proof of direct exposure by itself
- **TLS parameter checks on engines with incomplete parameter collection** -> do not claim enforcement is missing unless the parameter data proves it
- **Missing log exports on engines that do not support the same export set** -> evaluate engine capabilities before escalating

Always ask:
- Is the endpoint actually reachable?
- Is the snapshot actually shared?
- Is the DB actually important?
- Is the parameter evidence complete enough to prove the control state?

---

## 6. Severity Tuning Rules

### Raise severity when:
- DB is publicly accessible and SG is broad
- DB name/tags indicate customer, auth, payments, finance, prod, or backup usage
- Snapshot sharing affects production or sensitive sources
- Multiple findings combine into a confirmed attack path
- The same SG or subnet-group issue affects multiple DBs or cluster members
- Dependency context shows internet-facing EC2 instances that can reach the DB

### Lower severity when:
- DB is clearly dev/test and isolated
- Snapshot sharing is tightly scoped to a known backup account and encrypted
- Public placement is theoretical but direct reachability is not proven
- Finding is mostly hygiene or recoverability with no reachable attack path

---

## 7. Dependency Context Usage Rules (RDS Specific)

### You MAY:
- Use EC2/VPC data to confirm SG reachability, subnet intent, and public app-tier to DB relationships
- Use Secrets Manager data to confirm whether database credential secrets are present and named
- Use KMS data to confirm key state for referenced encryption keys
- Reference dependency data in `attack_paths[].chain[]` hops and remediation steps

### You MUST NOT:
- Perform a standalone EC2 security audit from dependency context
- Emit independent Secrets Manager or KMS findings unrelated to the RDS attack path
- Treat dependency context as a full scan of that service
- Invent application credentials, secret contents, or KMS key policies not in the scan

### When dependency context is missing:
- Note in the `narrative` that subnet, SG, or app-tier validation is incomplete
- Keep the RDS-direct finding and mention possible downstream risk in `impact`
- Do NOT create formal attack paths with more than 1 unexplained inference

---

## 8. Attack Path Construction Workflow

Follow this order when analyzing RDS scan output:

### Step 1: Build relationship maps (Section 2)
Map DBs, clusters, subnet groups, SGs, snapshots, parameter groups, and backup/logging controls first.

### Step 2: Identify direct findings (Section 3)
Walk through each RDS misconfiguration pattern and emit concrete `findings[]` entries.

### Step 3: Attempt attack path matching (Section 4)
For each exposed DB, shared snapshot, or weak recovery posture:
1. Check which reference attack paths apply
2. Validate each hop against actual scan evidence
3. Label each hop `CONFIRMED` or `INFERRED`
4. Count confirmed hops carefully
5. Only emit the path if it satisfies the evidence threshold

### Step 4: Cross-reference findings and paths
- Add `attack_path_ids` to findings that participate in formal attack paths
- Ensure the attack path references actual finding IDs and actual DB or snapshot identifiers

### Step 5: Rank remediation
- Break direct exposure first
- Then remove snapshot-sharing and plaintext data risk
- Then improve recovery and visibility

### Step 6: Write narrative and quick wins
- Narrative should reference the worst real DB or snapshot path
- Quick wins should prioritize internet exposure and snapshot-sharing fixes first

---

## 9. Remediation Playbooks

### Playbook: Remove Direct Database Exposure
1. Identify public DB instances and clusters
2. Revoke SG access from `0.0.0.0/0` and `::/0` on DB ports
3. Disable public accessibility
4. Verify DB subnet groups use private subnets only
5. Re-test application reachability from approved app tiers

### Playbook: Secure Manual Snapshots
1. Inventory all manual snapshots and cluster snapshots
2. Remove public sharing immediately
3. Review all named external account shares
4. Recreate or copy snapshots with encryption where required
5. Rotate any credentials or secrets likely stored in the data

### Playbook: Enforce Encryption and Secure Transport
1. Prioritize production and customer-data DBs
2. Plan encrypted restore/cutover for unencrypted databases
3. Update parameter groups to enforce secure transport
4. Schedule reboots or maintenance windows where the parameter family requires it

### Playbook: Improve Recoverability
1. Raise backup retention on important DBs
2. Enable deletion protection on production databases
3. Validate snapshot/restore procedures
4. Review who can create, share, and restore snapshots

### Playbook: Improve Detection and Investigation
1. Enable engine-appropriate CloudWatch log exports
2. Confirm log group retention and access controls
3. Prioritize public or app-reachable DBs first
4. Correlate DB visibility with network exposure findings

---

## 10. Output Guidance

### Finding output
- Refer to actual **DB identifiers, cluster identifiers, subnet group names, snapshot IDs, SG IDs, and ports**
- State whether the DB is public, which SG or subnet decision creates the risk, and whether the source looks production or sensitive
- Distinguish between **direct exposure**, **offline data exposure**, **weak recoverability**, and **visibility gaps**
- Use concise impact language that explains what an attacker gains
- Prefer specific CLI fixes when a direct AWS CLI action exists

### Attack path output
- `full_path_summary` must use real resources such as `Internet -> sg-0abc -> db-prod-01` or `snap-prod-2026-03-15 -> external-account-123456789012`
- Each `chain[]` hop must have `evidence_status`
- Each `INFERRED` hop must explain why it is inferred and what data would confirm it
- `remediation_priority` must list the shortest path to break the chain

**Good finding example**:
> Database `orders-prod-db` is `PubliclyAccessible=true` and security group `sg-0abc1234` allows port 5432 from `0.0.0.0/0`. This creates direct internet reachability to a production PostgreSQL endpoint.

**Bad finding example**:
> The database may be risky and should be reviewed.

---

## 11. Minimum RDS Coverage Checklist

A thorough RDS analysis must evaluate:

### Direct RDS findings:
- [ ] Publicly accessible DB instances or cluster members
- [ ] Internet-open SG rules on DB/admin ports
- [ ] DB subnet groups using public or mixed-intent subnets
- [ ] Storage encryption disabled
- [ ] Public manual snapshots
- [ ] Cross-account snapshot sharing
- [ ] Snapshot encryption posture
- [ ] Backup retention weakness
- [ ] Deletion protection disabled on important DBs
- [ ] Missing CloudWatch log exports
- [ ] TLS / secure-transport enforcement in parameter groups

### Attack path evaluation (using dependency context):
- [ ] Direct internet access to public RDS (AP-REF-01)
- [ ] Public RDS + no TLS enforcement (AP-REF-02)
- [ ] Public snapshot offline theft (AP-REF-03)
- [ ] Cross-account snapshot restore path (AP-REF-04)
- [ ] Public EC2 app tier to reachable RDS pivot (AP-REF-05)
- [ ] Architecture-driven exposure from public subnets (AP-REF-06)
- [ ] Public RDS + no log exports (AP-REF-07)
- [ ] Shared snapshot + no encryption (AP-REF-08)
- [ ] Public cluster endpoint exposure (AP-REF-09)
- [ ] Weak backups + no deletion protection destructive path (AP-REF-10)

If these are not evaluated, the RDS analysis is incomplete.
