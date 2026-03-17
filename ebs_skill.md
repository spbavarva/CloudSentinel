# EBS Security Analysis Skill - Attack Path Edition

## Service Overview

EBS is the primary block-storage persistence layer for EC2-backed workloads. The highest-value EBS risks are usually not about live network access. They are about what happens when volumes or snapshots can be copied, restored, mounted elsewhere, or left unencrypted.

This skill is designed for the **primary-service + dependency-context model** defined in `AGENTS.md` / `CLAUDE.md`. The EBS scanner Python file should use the EC2 AWS CLI namespace to collect EBS volume and snapshot evidence, plus minimal dependency context from EC2, AMI-related image metadata, and KMS. This skill tells CloudSentinel how to interpret that input and produce evidence-based findings and attack paths.

Primary goals:
1. Detect public or externally shared snapshots
2. Evaluate encryption on volumes, snapshots, and the regional default
3. Map snapshots back to attached workloads and AMIs
4. Distinguish active data-risk findings from stale hygiene findings
5. Validate only evidence-backed offline data-exposure paths

---

## 1. Input Layout and Interpretation

The EBS scanner Python file should run AWS CLI commands and deliver output in this structure:

```text
=== PRIMARY SERVICE: EBS ===
--- Command: describe-volumes ---
[output]
--- Command: describe-snapshots (owner self) ---
[output]
--- Command: describe-snapshot-attribute (createVolumePermission per snapshot) ---
[output]
--- Command: get-ebs-encryption-by-default ---
[output]
--- Command: get-ebs-default-kms-key-id ---
[output]
--- Command: get-snapshot-block-public-access-state ---
[output]

=== DEPENDENCY CONTEXT: EC2 ===
--- Command: describe-instances (for attached-volume context, tags, public reachability) ---
[output]
--- Command: describe-images (for snapshots backing owned AMIs) ---
[output]

=== DEPENDENCY CONTEXT: KMS ===
--- Command: describe-key (per referenced KMS key) ---
[output]
```

### Input Interpretation Rules

1. **PRIMARY SERVICE: EBS** is the full audit scope. Every volume, snapshot, and regional EBS setting in this section must be analyzed.
2. **DEPENDENCY CONTEXT** sections are supporting evidence only. Use them to understand attachment state, sensitivity, AMI lineage, and KMS key state.
3. Do NOT perform a standalone EC2, AMI, or KMS audit from dependency context.
4. Do NOT emit findings for dependency services unless a dependency misconfiguration is directly required to explain an EBS-centered attack path.
5. If a dependency section is missing or empty, do not assume it is secure or insecure. State what could not be evaluated.
6. Do NOT invent source instances, AMIs, or key policies not visible in the input.

### Output Contract Guardrails

- Return **valid JSON only**. Do not emit markdown fences or prose outside the JSON object.
- `findings[].severity` must always be one of `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.
- If evidence is ambiguous, keep the best-fit severity and set `findings[].status` to `NEEDS_REVIEW`.
- `quick_wins[]` entries must include `finding_id`, `action`, `effort`, and `impact`.
- `attack_paths[].id` must use `AP-{NUMBER}`, and every `full_path_summary` must use real volume IDs, snapshot IDs, instance IDs, image IDs, or key IDs from the scan.

---

## 2. Relationship Mapping (Do This First)

Before generating any findings or attack paths, build these maps from the scan data:

### EBS Resource Maps
- **Volume -> Attachment State**: attached instance, device name, or unattached
- **Volume -> Encryption**: encrypted or not, `KmsKeyId` if present
- **Volume -> Snapshot Lineage**: source snapshot when visible
- **Volume -> Size / Type / Tags**: production and sensitivity indicators
- **Snapshot -> Source Volume**: snapshot lineage and source workload
- **Snapshot -> Sharing**: public (`all`) vs named external accounts
- **Snapshot -> Encryption**: encrypted or plaintext
- **Region -> Encryption by Default**: on or off
- **Region -> Default KMS Key**: AWS-managed or customer-managed key ID
- **Region -> Snapshot Block Public Access**: block state or disabled

### Dependency Maps (from dependency context)
- **Volume -> EC2 Instance**: which instance the volume is attached to, and whether that instance is public, production, database, or otherwise high value
- **Snapshot -> AMI**: whether a snapshot backs an owned AMI
- **KMS Key -> Key State**: enabled, disabled, pending deletion

### Derived Relationships
- **Active Sensitive Volume**: attached to a production or sensitive instance
- **Offline Breach Path**: snapshot sharing proves restore/copy path outside the workload boundary
- **Image Supply Path**: snapshot backs an owned AMI, increasing blast radius
- **Regional Guardrail Gap**: encryption-by-default disabled or snapshot public block disabled

Always separate:
- **Data exposure** through shared snapshots
- **Data-at-rest protection**
- **Lifecycle hygiene** for stale assets

---

## 3. EBS Direct Findings - Misconfiguration Patterns

These are direct findings in the primary EBS service. Each pattern produces a `findings[]` entry.

### Pattern EBS-VOLUME-UNENCRYPTED: Unencrypted EBS Volume
- **Detection**: `Encrypted: false` on a volume
- **Category**: `encryption`
- **Base severity**: MEDIUM
- **Severity modifiers**:
  - Attached to a production, database, auth, or customer-data instance -> HIGH
  - Detached empty/test volume -> LOW
- **Impact**: Data at rest lacks cryptographic protection. Snapshot misuse or storage leakage exposes plaintext data.
- **Fix**: EBS volumes cannot be encrypted in place. Snapshot the volume, copy the snapshot with encryption enabled, create a new encrypted volume, and replace the original.
- **Attack path role**: Amplifies the impact of snapshot exposure

### Pattern EBS-SNAPSHOT-PUBLIC: Snapshot Shared Publicly
- **Detection**: `createVolumePermission` includes group `all`
- **Category**: `data_exposure`
- **Base severity**: CRITICAL
- **Impact**: Any AWS account can copy the snapshot, create a volume from it, and mount the data offline.
- **Fix**: `aws ec2 modify-snapshot-attribute --snapshot-id {snapshot-id} --attribute createVolumePermission --operation-type remove --group-names all`
- **Attack path role**: Direct offline data theft path

### Pattern EBS-SNAPSHOT-CROSS-ACCOUNT: Snapshot Shared to External Account
- **Detection**: `createVolumePermission` includes external AWS account IDs
- **Category**: `access_control`
- **Base severity**: HIGH
- **Status rule**: Use `NEEDS_REVIEW` when the sharing appears to be a controlled backup-account or DR workflow and the available evidence cannot validate that intent.
- **Severity modifiers**:
  - Source workload is sensitive or production -> raise one level
  - Snapshot is also unencrypted -> CRITICAL
- **Impact**: Snapshot data can be restored outside the account boundary.
- **Fix**: `aws ec2 modify-snapshot-attribute --snapshot-id {snapshot-id} --attribute createVolumePermission --operation-type remove --user-ids {account-id}`
- **Attack path role**: External restore path

### Pattern EBS-SNAPSHOT-UNENCRYPTED: Snapshot Not Encrypted
- **Detection**: `Encrypted: false` on a snapshot
- **Category**: `encryption`
- **Base severity**: MEDIUM
- **Severity modifiers**:
  - Snapshot is public or externally shared -> CRITICAL
  - Source is production/sensitive -> HIGH
- **Impact**: Shared or leaked snapshots expose plaintext data.
- **Fix**: `aws ec2 copy-snapshot --source-region {region} --source-snapshot-id {snapshot-id} --encrypted --kms-key-id {kms-key-id}`
- **Attack path role**: Amplifies snapshot-sharing exposure

### Pattern EBS-ENCRYPTION-DEFAULT-OFF: EBS Encryption by Default Disabled
- **Detection**: `get-ebs-encryption-by-default` returns disabled
- **Category**: `encryption`
- **Base severity**: HIGH
- **Impact**: New volumes and copied snapshots may be created without encryption unless operators remember to set it every time.
- **Fix**: `aws ec2 enable-ebs-encryption-by-default`
- **Attack path role**: Governance weakness that allows future plaintext storage creation

### Pattern EBS-SNAPSHOT-BLOCK-PUBLIC-OFF: Snapshot Block Public Access Disabled
- **Detection**: `get-snapshot-block-public-access-state` is absent, permissive, or not blocking public sharing
- **Category**: `access_control`
- **Base severity**: HIGH
- **Impact**: The account lacks the guardrail that prevents accidental or deliberate public snapshot sharing.
- **Fix**: `aws ec2 enable-snapshot-block-public-access --state block-all-sharing`
- **Attack path role**: Account-wide enabler for snapshot exposure

### Pattern EBS-KMS-KEY-RISK: Referenced Customer-Managed KMS Key Disabled or Pending Deletion
- **Detection**: Dependency context shows the referenced CMK is disabled or pending deletion
- **Category**: `compliance`
- **Base severity**: MEDIUM
- **Status rule**: Use `NEEDS_REVIEW` when the key state is visible but the effect on current workloads cannot be fully validated from the scan.
- **Impact**: Encryption exists, but the key lifecycle may create restore or availability problems and weak operational control.
- **Fix**: Re-enable the KMS key or re-encrypt on a healthy key after validating workload impact
- **Attack path role**: Not usually a direct attack path; keep as a direct finding unless it materially changes a confirmed chain

### Pattern EBS-VOLUME-STALE: Detached Volume Appears Stale
- **Detection**: Volume is unattached and tags/age suggest it is not part of an active workflow
- **Category**: `resource_hygiene`
- **Base severity**: LOW
- **Severity modifiers**:
  - Volume is large and unencrypted -> MEDIUM
  - Volume name/tags suggest production backup or sensitive content -> MEDIUM
- **Impact**: Detached storage increases untracked data sprawl and can become a later exposure source.
- **Fix**: Validate ownership and either attach, snapshot/archive securely, or delete

### Pattern EBS-SNAPSHOT-STALE: Snapshot Appears Unused and Unowned
- **Detection**: Snapshot has no clear current owner, AMI linkage, or workload relationship
- **Category**: `resource_hygiene`
- **Base severity**: LOW
- **Severity modifiers**:
  - Snapshot is unencrypted or externally shared -> raise based on exposure
- **Impact**: Old snapshots accumulate sensitive data outside normal workload awareness.
- **Fix**: Validate ownership, then delete or migrate to an approved backup policy

---

## 4. EBS Attack Path Reference Catalog

These are the **reference attack paths** that CloudSentinel should attempt to match against actual scan evidence. A path from this catalog may ONLY be emitted as a formal `attack_paths[]` entry if it meets the evidence threshold from `AGENTS.md` / `CLAUDE.md`.

---

### AP-REF-01: Public Snapshot Offline Data Theft

**Pattern**: Public Snapshot -> Copy -> New Volume -> Offline Mount

**Chain hops**:
1. **Entry**: Snapshot is public
2. **Restore Path**: Public sharing proves any AWS account can copy or create a volume
3. **Sensitive Source**: Snapshot maps to a sensitive volume or instance

**Evidence requirements**:
- Hop 1 CONFIRMED: snapshot permission includes `all`
- Hop 2 CONFIRMED: the sharing model itself proves restore capability
- Hop 3 CONFIRMED if source volume or attached instance context shows importance; INFERRED otherwise

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED.

**Impact**: An attacker can restore the snapshot in their own account and inspect the filesystem, databases, keys, or application data offline.

**Remediation priority**:
1. Remove public snapshot sharing immediately
2. Review all snapshots from the same source volume
3. Rotate any credentials likely stored on disk

---

### AP-REF-02: Cross-Account Snapshot Restore Outside Intended Boundary

**Pattern**: External Account Share -> Copy / Restore -> Data Leaves Account

**Chain hops**:
1. **Share**: Snapshot is shared with one or more named external accounts
2. **Restore Path**: Named accounts can create volumes from the snapshot
3. **Sensitive Source**: Snapshot maps to an important workload

**Evidence requirements**:
- Hop 1 CONFIRMED: account IDs in snapshot permissions
- Hop 2 CONFIRMED: shared snapshot permissions prove restore capability
- Hop 3 CONFIRMED if the source workload is clearly important; INFERRED otherwise

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED.

**Impact**: Data can be restored outside the primary account boundary, even without compromising the running workload.

**Remediation priority**:
1. Remove unnecessary external account shares
2. Validate backup-account requirements
3. Keep only tightly justified sharing

---

### AP-REF-03: Public Snapshot + No Encryption = Plaintext Offline Breach

**Pattern**: Public Snapshot -> Plaintext Restore -> Offline Data Extraction

**Chain hops**:
1. **Snapshot Exposure**: Snapshot is public
2. **No Encryption**: Snapshot is unencrypted
3. **Sensitive Source**: Snapshot maps to an important workload

**Evidence requirements**:
- Hop 1 CONFIRMED: public sharing visible
- Hop 2 CONFIRMED: encryption state visible
- Hop 3 CONFIRMED if source workload context proves importance; INFERRED otherwise

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED.

**Impact**: Public exposure is worsened by plaintext storage, making offline review of the data straightforward after restore.

**Remediation priority**:
1. Remove public sharing
2. Replace with encrypted snapshot copies
3. Review and contain historical copies

---

### AP-REF-04: Shared Snapshot Backing an Owned AMI

**Pattern**: Exposed Snapshot -> Backing AMI -> Wider Image Blast Radius

**Chain hops**:
1. **Exposure**: Snapshot is public or externally shared
2. **AMI Linkage**: Dependency context shows the snapshot backs an owned AMI
3. **Broader Impact**: The image may be reused across multiple workloads

**Evidence requirements**:
- Hop 1 CONFIRMED: sharing visible
- Hop 2 CONFIRMED: `describe-images` dependency context maps the snapshot to an AMI
- Hop 3 CONFIRMED if the AMI is in active use; INFERRED otherwise

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED.

**Impact**: Snapshot exposure leaks not just one volume, but a base image used by multiple systems.

**Remediation priority**:
1. Remove snapshot sharing
2. Review the AMI and any derived images
3. Rebuild on encrypted and private storage

---

### AP-REF-05: Sensitive Attached Volume -> Snapshot Exposure -> Offline Data Theft

**Pattern**: Production Volume -> Public or Shared Snapshot -> Data Breach

**Chain hops**:
1. **Sensitive Source**: Attached volume belongs to a production or sensitive instance
2. **Snapshot Exposure**: Snapshot from that volume is public or externally shared
3. **Restore Path**: Snapshot can be copied or restored outside the account

**Evidence requirements**:
- Hop 1 CONFIRMED: instance attachment and tags visible in dependency context
- Hop 2 CONFIRMED: snapshot permissions visible
- Hop 3 CONFIRMED: sharing proves restore capability

**Minimum for formal path**: All three hops should be CONFIRMED.

**Impact**: Data from an active high-value workload can be extracted offline without compromising the instance itself.

**Remediation priority**:
1. Remove snapshot exposure
2. Review the attached instance and all recent snapshots
3. Rotate secrets likely stored on disk

---

### AP-REF-06: Snapshot Block Public Access Disabled + Public Snapshot

**Pattern**: Missing Guardrail -> Public Snapshot Exists -> Repeated Exposure Risk

**Chain hops**:
1. **Guardrail Gap**: snapshot block public access is not enforced
2. **Current Exposure**: at least one snapshot is public
3. **Account-Wide Risk**: the same mistake can recur for future snapshots

**Evidence requirements**:
- Hop 1 CONFIRMED: regional setting visible
- Hop 2 CONFIRMED: public snapshot exists
- Hop 3 INFERRED: future recurrence is the operational implication

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED.

**Impact**: The account lacks both the preventive guardrail and already has a live public snapshot exposure.

**Remediation priority**:
1. Enable snapshot block public access
2. Remove all current public shares
3. Review snapshot-creation automation

---

### AP-REF-07: Encryption by Default Disabled -> Future Plaintext Volume Creation

**Pattern**: No Regional Encryption Default -> New Volumes / Copies May Be Plaintext

**Chain hops**:
1. **Guardrail Gap**: encryption by default is disabled
2. **Evidence of Plaintext Assets**: one or more current volumes or snapshots are unencrypted
3. **Operational Repeatability**: future assets may inherit the same weakness

**Evidence requirements**:
- Hop 1 CONFIRMED: regional setting visible
- Hop 2 CONFIRMED: unencrypted assets exist
- Hop 3 INFERRED: future recurrence is the operational implication

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED.

**Impact**: The account is not relying on a preventive control, so plaintext storage can continue to appear through human error or automation drift.

**Remediation priority**:
1. Enable encryption by default
2. Prioritize migration of sensitive unencrypted volumes and snapshots
3. Review image and backup pipelines

---

## 5. False Positive and Context Controls

Do **NOT** overstate the following:

- **Snapshot shares to a dedicated backup account** -> use `NEEDS_REVIEW` unless sharing is broad, public, or unjustified
- **Detached lab or migration volumes** -> keep as LOW unless other evidence shows sensitive data
- **Archive snapshots** -> stale hygiene, not a critical issue by itself
- **KMS key state warnings** -> do not convert into attack paths unless the key issue materially changes a confirmed exposure chain

Always ask:
- Is the snapshot actually exposed outside the account?
- Is the source workload clearly important?
- Is the issue active data risk or only hygiene?

---

## 6. Severity Tuning Rules

### Raise severity when:
- Snapshot is public
- Snapshot is shared and unencrypted
- Source volume maps to production, database, auth, or customer-data workloads
- The same exposure affects multiple snapshots or images
- Regional guardrails are disabled and live exposures already exist

### Lower severity when:
- Asset is clearly test, empty, or dormant
- Sharing is tightly limited to a justified backup account
- The issue is primarily hygiene with no exposure path

---

## 7. Dependency Context Usage Rules (EBS Specific)

### You MAY:
- Use EC2 data to determine whether a volume is attached, public-facing, and important
- Use image data to determine whether a snapshot backs an AMI
- Use KMS data to determine key state
- Reference dependency data in `attack_paths[].chain[]` and remediation

### You MUST NOT:
- Perform a standalone EC2 or AMI audit from dependency context
- Emit unrelated KMS findings not tied to the EBS issue
- Invent filesystem contents, application secrets, or workload purpose not supported by tags and context

### When dependency context is missing:
- Keep the snapshot or encryption finding
- Note that source-workload sensitivity could not be fully validated
- Do NOT create formal attack paths with more than 1 unexplained inference

---

## 8. Attack Path Construction Workflow

Follow this order when analyzing EBS scan output:

### Step 1: Build relationship maps (Section 2)
Map volumes, snapshots, source workloads, regional guardrails, and AMI linkage first.

### Step 2: Identify direct findings (Section 3)
Emit all snapshot-sharing, encryption, and stale-storage findings.

### Step 3: Attempt attack path matching (Section 4)
Focus on offline restore and copy paths, not speculative live network compromise.

### Step 4: Cross-reference findings and paths
- Attach `attack_path_ids` where formal paths exist
- Ensure every path uses real volume, snapshot, image, or instance identifiers

### Step 5: Rank remediation
- Remove public sharing first
- Then external sharing and plaintext exposures
- Then regional guardrails
- Then lifecycle hygiene

### Step 6: Write narrative and quick wins
- Lead with the most dangerous public or shared snapshot
- Prefer fast actions that stop data leaving the account

---

## 9. Remediation Playbooks

### Playbook: Remove Snapshot Exposure
1. Inventory all public and externally shared snapshots
2. Remove public sharing immediately
3. Remove unnecessary external account shares
4. Review whether the same source volume has additional snapshots
5. Rotate any credentials likely stored on the exposed disks

### Playbook: Enforce Encryption Guardrails
1. Enable EBS encryption by default
2. Validate the default KMS key
3. Recreate sensitive snapshots as encrypted copies
4. Rebuild critical unencrypted volumes onto encrypted storage

### Playbook: Prevent Future Public Sharing
1. Enable snapshot block public access
2. Audit image and backup automation
3. Alert on `ModifySnapshotAttribute` and public-sharing attempts

### Playbook: Clean Up Stale Storage Safely
1. Identify detached volumes and orphaned snapshots
2. Confirm ownership before deletion
3. Archive securely if retention is required
4. Remove stale assets from active regions when no longer needed

---

## 10. Output Guidance

### Finding output
- Refer to actual **volume IDs, snapshot IDs, instance IDs, AMI IDs, and KMS key IDs**
- State whether the asset is attached, public/shared, encrypted, and what workload or image it maps to
- Separate **offline data exposure** from **regional guardrail** issues and **lifecycle hygiene**
- Use concise impact language focused on what an attacker can restore or read

### Attack path output
- `full_path_summary` should look like `snap-0123 -> attacker-account -> vol-0456` or `vol-0abc -> snap-0def -> ami-0123`
- Each `INFERRED` hop must explain what extra data would confirm it
- `remediation_priority` should start with removing exposure, not cleaning up stale assets

---

## 11. Minimum EBS Coverage Checklist

A thorough EBS analysis must evaluate:

### Direct EBS findings:
- [ ] Unencrypted attached volumes
- [ ] Public snapshots
- [ ] Cross-account shared snapshots
- [ ] Unencrypted snapshots
- [ ] EBS encryption by default
- [ ] Default KMS key posture
- [ ] Snapshot block public access state
- [ ] Stale detached volumes
- [ ] Stale or orphaned snapshots
- [ ] Snapshot-to-AMI linkage for broader blast radius

### Attack path evaluation (using dependency context):
- [ ] Public snapshot offline theft (AP-REF-01)
- [ ] Cross-account snapshot restore path (AP-REF-02)
- [ ] Public snapshot + no encryption (AP-REF-03)
- [ ] Exposed snapshot backing an AMI (AP-REF-04)
- [ ] Sensitive attached volume to exposed snapshot path (AP-REF-05)
- [ ] Missing public-sharing guardrail + live public snapshot (AP-REF-06)
- [ ] Encryption-by-default disabled with plaintext assets (AP-REF-07)

If these are not evaluated, the EBS analysis is incomplete.
