# AMI Security Analysis Skill - Attack Path Edition

## Service Overview

AMI is the image-distribution layer for EC2-based workloads. The most important AMI risks are broad launch permissions, exposed backing snapshots, unsafe instance defaults baked into the image, and stale or over-shared golden images that spread weak posture across many hosts.

This skill is designed for the **primary-service + dependency-context model** defined in `AGENTS.md` / `CLAUDE.md`. The AMI scanner Python file should use the EC2 AWS CLI namespace to collect AMI metadata plus minimal dependency context from snapshots, instances, launch templates, and Auto Scaling. This skill tells CloudSentinel how to interpret that input and produce evidence-based findings and attack paths.

Primary goals:
1. Detect public and broad cross-account AMI sharing
2. Evaluate backing-snapshot exposure and encryption
3. Check whether AMIs enforce safer launch defaults such as IMDSv2
4. Measure the blast radius of images in active use
5. Validate only evidence-backed image-distribution attack paths

---

## 1. Input Layout and Interpretation

The AMI scanner Python file should run AWS CLI commands and deliver output in this structure:

```text
=== PRIMARY SERVICE: AMI ===
--- Command: describe-images (owners self) ---
[output]
--- Command: describe-image-attribute (launchPermission per image) ---
[output]
--- Command: describe-image-attribute (imdsSupport per image) ---
[output]
--- Command: describe-image-attribute (deregistrationProtection per image) ---
[output]

=== DEPENDENCY CONTEXT: EC2 ===
--- Command: describe-snapshots (backing snapshots for owned AMIs) ---
[output]
--- Command: describe-snapshot-attribute (createVolumePermission per backing snapshot) ---
[output]
--- Command: describe-instances (instances launched from owned AMIs) ---
[output]
--- Command: describe-launch-templates ---
[output]
--- Command: describe-launch-template-versions (active versions referencing owned AMIs) ---
[output]

=== DEPENDENCY CONTEXT: AUTOSCALING ===
--- Command: describe-auto-scaling-groups (groups using owned AMIs through launch templates/configurations) ---
[output]
```

### Input Interpretation Rules

1. **PRIMARY SERVICE: AMI** is the full audit scope. Every owned image and its key attributes in this section must be analyzed.
2. **DEPENDENCY CONTEXT** sections are supporting evidence only. Use them to understand backing snapshots, image usage, and fleet blast radius.
3. Do NOT perform a standalone EC2 or Auto Scaling audit from dependency context.
4. Do NOT emit findings for dependency services unless a dependency misconfiguration is directly required to explain an AMI-centered attack path.
5. If a dependency section is missing or empty, do not assume it is secure or insecure. State what could not be evaluated.
6. Do NOT invent filesystem contents or embedded secrets that are not supported by the scan.

### Output Contract Guardrails

- Return **valid JSON only**. Do not emit markdown fences or prose outside the JSON object.
- `findings[].severity` must always be one of `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.
- If evidence is ambiguous, keep the best-fit severity and set `findings[].status` to `NEEDS_REVIEW`.
- `quick_wins[]` entries must include `finding_id`, `action`, `effort`, and `impact`.
- `attack_paths[].id` must use `AP-{NUMBER}`, and every `full_path_summary` must use real AMI IDs, snapshot IDs, launch template IDs, or instance IDs from the scan.

---

## 2. Relationship Mapping (Do This First)

Before generating any findings or attack paths, build these maps from the scan data:

### AMI Resource Maps
- **AMI -> Launch Permission**: private, public, or shared to named accounts
- **AMI -> IMDS Support**: `v2.0` or not enforced
- **AMI -> Deregistration Protection**: enabled or not
- **AMI -> Backing Snapshots**: snapshot IDs from block device mappings
- **AMI -> Age / Creation Date**: used for stale-image review
- **AMI -> Tags / Name / Description**: sensitivity and purpose indicators (`golden`, `base`, `prod`, `internal`, `customer`, `payments`)
- **AMI -> State / Deprecation**: available, deprecated where visible

### Dependency Maps (from dependency context)
- **AMI -> Backing Snapshot Exposure**: whether backing snapshots are public, shared, or unencrypted
- **AMI -> Running Instances**: how many active instances still use the AMI
- **AMI -> Launch Templates**: whether the AMI is the active template source
- **AMI -> Auto Scaling Groups**: whether the image is feeding a fleet

### Derived Relationships
- **Public Internal Image**: public launch permission + internal/golden/prod naming
- **Image Supply Blast Radius**: AMI is referenced by launch templates or ASGs
- **Snapshot-Backed Exposure**: backing snapshots are public/shared or unencrypted
- **Default Credential-Risk Multiplier**: IMDSv2 not required on a heavily used image

Always distinguish between:
- **Image-sharing risk**
- **Backing-data exposure**
- **Unsafe launch defaults**
- **Lifecycle hygiene**

---

## 3. AMI Direct Findings - Misconfiguration Patterns

These are direct findings in the primary AMI service. Each pattern produces a `findings[]` entry.

### Pattern AMI-PUBLIC: AMI Shared Publicly
- **Detection**: launch permissions include group `all` or the AMI is otherwise clearly public
- **Category**: `data_exposure`
- **Base severity**: HIGH
- **Severity modifiers**:
  - Name/tags imply internal, prod, base, golden, app, auth, customer, or payments image -> CRITICAL
  - Backing snapshots are also public or unencrypted -> CRITICAL
- **Impact**: Any AWS account can launch a copy of the image and inspect its configuration, software stack, and included files.
- **Fix**: `aws ec2 modify-image-attribute --image-id {ami-id} --launch-permission "Remove=[{Group=all}]"`
- **Attack path role**: Direct image-cloning exposure path

### Pattern AMI-CROSS-ACCOUNT: AMI Shared to External Account
- **Detection**: launch permissions include named external AWS account IDs
- **Category**: `access_control`
- **Base severity**: HIGH
- **Status rule**: Use `NEEDS_REVIEW` when the image appears to be part of a controlled organization-wide sharing model and the business justification cannot be proven from the scan.
- **Severity modifiers**:
  - Golden/internal/prod image -> raise one level
  - Backing snapshots are broadly exposed -> CRITICAL
- **Impact**: The image can be launched outside the expected boundary.
- **Fix**: `aws ec2 modify-image-attribute --image-id {ami-id} --launch-permission "Remove=[{UserId={account-id}}]"`
- **Attack path role**: External deployment path for internal images

### Pattern AMI-BACKING-SNAPSHOT-PUBLIC: Backing Snapshot Shared Publicly
- **Detection**: One or more block-device snapshots for the AMI are public
- **Category**: `data_exposure`
- **Base severity**: CRITICAL
- **Impact**: The image's filesystem data can be restored offline through the exposed snapshot even if the AMI itself is later made private.
- **Fix**: Remove public sharing from the backing snapshot and rebuild the image if necessary
- **Attack path role**: Stronger offline data exposure path than AMI sharing alone

### Pattern AMI-BACKING-SNAPSHOT-UNENCRYPTED: Backing Snapshot Not Encrypted
- **Detection**: One or more backing snapshots have `Encrypted: false`
- **Category**: `encryption`
- **Base severity**: MEDIUM
- **Severity modifiers**:
  - Snapshot is public or externally shared -> CRITICAL
  - AMI is golden/internal/prod -> HIGH
- **Impact**: Image data is stored in plaintext at the snapshot layer.
- **Fix**: Rebuild the AMI from encrypted snapshot copies
- **Attack path role**: Amplifies image-sharing and snapshot-sharing exposure

### Pattern AMI-IMDSV2-NOT-REQUIRED: AMI Does Not Require IMDSv2
- **Detection**: `imdsSupport` is absent or not `v2.0`
- **Category**: `credential_risk`
- **Base severity**: MEDIUM
- **Severity modifiers**:
  - AMI is used by active launch templates or ASGs -> HIGH
  - AMI looks like the base image for public web fleets -> HIGH
- **Impact**: New instances launched from the image may allow IMDSv1-style credential theft paths unless instance-level overrides harden them later.
- **Fix**: `aws ec2 modify-image-attribute --image-id {ami-id} --imds-support v2.0`
- **Attack path role**: Multiplies future credential-theft exposure across fleets

### Pattern AMI-DEREG-PROTECTION-OFF: Deregistration Protection Disabled on Critical Image
- **Detection**: `deregistrationProtection` is disabled on a golden or actively used image
- **Category**: `resource_hygiene`
- **Base severity**: LOW
- **Severity modifiers**:
  - Image is referenced by active launch templates or ASGs -> MEDIUM
  - Image is clearly golden/base/prod -> MEDIUM
- **Impact**: Important images can be removed accidentally or maliciously, weakening deployment resilience.
- **Fix**: `aws ec2 enable-image-deregistration-protection --image-id {ami-id}`

### Pattern AMI-STALE-UNUSED: Old Unused AMI Retained Without Clear Ownership
- **Detection**: AMI is old, not referenced by instances, launch templates, or ASGs, and ownership is unclear
- **Category**: `resource_hygiene`
- **Base severity**: LOW
- **Impact**: Old images accumulate sensitive software and configuration state outside normal review.
- **Fix**: Validate ownership, then deprecate or `aws ec2 deregister-image --image-id {ami-id}`

### Pattern AMI-OLD-IN-USE: Old Image Still Drives Active Fleet
- **Detection**: Creation date is old and the AMI is still used by active instances, launch templates, or ASGs
- **Category**: `compliance`
- **Base severity**: MEDIUM
- **Status rule**: Use `NEEDS_REVIEW` unless the age clearly represents an unmaintained image baseline rather than an intentionally frozen appliance.
- **Impact**: Older image baselines increase the chance that fleets are lagging behind current hardening and patch expectations.
- **Fix**: Validate the image pipeline, rebuild a current base image, and roll forward safely

---

## 4. AMI Attack Path Reference Catalog

These are the **reference attack paths** that CloudSentinel should attempt to match against actual scan evidence. A path from this catalog may ONLY be emitted as a formal `attack_paths[]` entry if it meets the evidence threshold from `AGENTS.md` / `CLAUDE.md`.

---

### AP-REF-01: Public AMI Clone of Internal Stack

**Pattern**: Public AMI -> External Launch -> Internal Stack Exposure

**Chain hops**:
1. **Entry**: AMI is public
2. **Image Content Signal**: Name, tags, or description indicate internal or production use
3. **External Launch Path**: Public launch permission allows any AWS account to run it

**Evidence requirements**:
- Hop 1 CONFIRMED: public launch permission visible
- Hop 2 CONFIRMED if tags/names clearly indicate internal use; INFERRED otherwise
- Hop 3 CONFIRMED: public launch permission itself proves external launch capability

**Minimum for formal path**: Hops 1 and 3 must be CONFIRMED.

**Impact**: Attackers can launch the image in their own account and inspect the internal application stack, agents, configuration, and software versions.

**Remediation priority**:
1. Remove public launch permission
2. Review whether any backing snapshots are also exposed
3. Rotate any secrets that may have been embedded

---

### AP-REF-02: Cross-Account Shared AMI Outside Intended Boundary

**Pattern**: External Account AMI Share -> Unauthorized Launch -> Internal Image Exposure

**Chain hops**:
1. **Share**: AMI is shared with one or more external account IDs
2. **Launch Capability**: Shared accounts can launch the image
3. **Sensitive Image**: Image appears internal, golden, or production-relevant

**Evidence requirements**:
- Hop 1 CONFIRMED: account IDs visible in launch permissions
- Hop 2 CONFIRMED: launch permissions prove external launch capability
- Hop 3 CONFIRMED if image naming/tags indicate sensitivity; INFERRED otherwise

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED.

**Impact**: Internal images can be deployed in other accounts without additional compromise.

**Remediation priority**:
1. Remove unnecessary external shares
2. Keep only tightly scoped org-approved sharing
3. Review which workloads or teams still rely on the image

---

### AP-REF-03: Public AMI + Public Backing Snapshot

**Pattern**: Public AMI -> Public Snapshot -> Strong Offline Extraction Path

**Chain hops**:
1. **AMI Exposure**: AMI is public or broadly shared
2. **Backing Snapshot Exposure**: one or more backing snapshots are public
3. **Offline Restore**: Exposed snapshot provides direct filesystem extraction path

**Evidence requirements**:
- Hop 1 CONFIRMED: launch permission visible
- Hop 2 CONFIRMED: snapshot permission visible in dependency context
- Hop 3 CONFIRMED: public snapshot sharing proves offline restore capability

**Minimum for formal path**: All three hops should be CONFIRMED.

**Impact**: Attackers do not need to rely on the AMI launch path alone; they can restore the underlying filesystem directly from the snapshot.

**Remediation priority**:
1. Remove public AMI and snapshot sharing
2. Rebuild the image from private, encrypted storage
3. Review all derivative images and copies

---

### AP-REF-04: Shared AMI + Unencrypted Backing Snapshot

**Pattern**: External Image Share -> Plaintext Snapshot Layer -> Broader Data Exposure

**Chain hops**:
1. **AMI Exposure**: AMI is public or externally shared
2. **Backing Snapshot Plaintext**: snapshot is unencrypted
3. **Image Content Importance**: image is internal or in active use

**Evidence requirements**:
- Hop 1 CONFIRMED: launch permissions visible
- Hop 2 CONFIRMED: snapshot encryption state visible
- Hop 3 CONFIRMED if the image is clearly important; INFERRED otherwise

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED.

**Impact**: The image's underlying storage is easier to restore and inspect after exposure because the snapshot layer lacks encryption.

**Remediation priority**:
1. Remove image sharing
2. Rebuild on encrypted snapshots
3. Retire the exposed image IDs

---

### AP-REF-05: Golden AMI Without IMDSv2 Drives Fleet-Wide Credential Risk

**Pattern**: Weak Image Default -> Launch Templates / ASGs Use It -> Future Instances Inherit IMDSv1 Risk

**Chain hops**:
1. **Weak Default**: AMI does not require IMDSv2
2. **Fleet Usage**: launch templates or ASGs reference the AMI
3. **Broad Rollout**: new instances launched from the image may inherit the weak metadata posture

**Evidence requirements**:
- Hop 1 CONFIRMED: `imdsSupport` not `v2.0`
- Hop 2 CONFIRMED: dependency context shows launch template or ASG usage
- Hop 3 INFERRED: future launches inherit the image-level default unless overridden

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED.

**Impact**: The image pipeline spreads a weaker metadata-security default across current and future instances, increasing credential-theft risk at scale.

**Remediation priority**:
1. Enforce IMDSv2 at the image level
2. Roll forward launch templates and ASGs
3. Validate that instance-level overrides do not reintroduce the weakness

---

### AP-REF-06: Public Internal Image in Active Use

**Pattern**: Public AMI -> Running Instances Use Same Image -> Live and Cloneable Environment

**Chain hops**:
1. **Image Exposure**: AMI is public
2. **Active Usage**: running instances use the AMI
3. **Shared Baseline**: external attackers can launch an environment close to the running fleet

**Evidence requirements**:
- Hop 1 CONFIRMED: public launch permission visible
- Hop 2 CONFIRMED: dependency context shows running instances on the AMI
- Hop 3 INFERRED: similarity of cloned and running environments depends on local drift

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED.

**Impact**: Attackers can clone a close approximation of the production baseline for reconnaissance, tooling development, and configuration review.

**Remediation priority**:
1. Remove public launch permission
2. Review image contents and derived instances
3. Rebuild and rotate sensitive baselines if needed

---

### AP-REF-07: Shared AMI Feeds Auto Scaling Fleet

**Pattern**: Broad Image Share -> ASG Uses Image -> Wide Deployment Blast Radius

**Chain hops**:
1. **Exposure**: AMI is public or externally shared
2. **Fleet Path**: Auto Scaling groups use the AMI through launch templates/configurations
3. **Scale Impact**: the same weak or exposed image baseline is multiplied across a fleet

**Evidence requirements**:
- Hop 1 CONFIRMED: launch permission visible
- Hop 2 CONFIRMED: ASG dependency context shows usage
- Hop 3 CONFIRMED if desired/current capacity indicates active use; INFERRED otherwise

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED.

**Impact**: Exposure or unsafe defaults in the image propagate across multiple instances instead of a single host.

**Remediation priority**:
1. Remove unnecessary image sharing
2. Roll forward ASGs to a hardened image
3. Retire the exposed image from active templates

---

## 5. False Positive and Context Controls

Do **NOT** overstate the following:

- **Intentional marketplace or public base images** -> use `NEEDS_REVIEW` unless internal naming/tags show they are proprietary or sensitive
- **Organization-approved cross-account golden-image sharing** -> keep as `NEEDS_REVIEW` unless sharing is broader than intended
- **Old images kept for controlled rollback** -> hygiene finding, not a critical exposure unless they are also shared or actively used unsafely
- **IMDSv2 image setting without usage data** -> still important, but severity should be lower when the AMI is clearly dormant

Always ask:
- Is the image actually broad enough to leave the account boundary?
- Do the backing snapshots make the exposure worse?
- Is the image driving an active fleet or just retained as history?

---

## 6. Severity Tuning Rules

### Raise severity when:
- AMI is public and clearly internal
- Backing snapshots are public or unencrypted
- Image is referenced by launch templates, ASGs, or active instances
- The AMI appears to be a golden/base image used widely

### Lower severity when:
- Image is intentionally public and clearly generic
- Cross-account sharing is tightly limited to known organizational consumers
- Finding is mostly lifecycle hygiene with no broad sharing or active usage

---

## 7. Dependency Context Usage Rules (AMI Specific)

### You MAY:
- Use snapshot data to evaluate backing-snapshot exposure and encryption
- Use instance, launch-template, and ASG data to measure blast radius and active usage
- Reference dependency data in `attack_paths[].chain[]` and remediation

### You MUST NOT:
- Perform a standalone EC2, Auto Scaling, or snapshot audit from dependency context
- Invent filesystem secrets or vulnerable software inside the AMI without evidence
- Treat dependency context as a full scan of that service

### When dependency context is missing:
- Keep the launch-permission and IMDS findings
- Note that backing-snapshot exposure or fleet blast radius could not be fully evaluated
- Do NOT create formal attack paths with more than 1 unexplained inference

---

## 8. Attack Path Construction Workflow

Follow this order when analyzing AMI scan output:

### Step 1: Build relationship maps (Section 2)
Map launch permissions, backing snapshots, image age, and active usage.

### Step 2: Identify direct findings (Section 3)
Emit image-sharing, snapshot-layer, unsafe-default, and stale-image findings.

### Step 3: Attempt attack path matching (Section 4)
Focus on image cloning, snapshot restore, and fleet-wide weak-default propagation.

### Step 4: Cross-reference findings and paths
- Attach `attack_path_ids` where formal paths exist
- Use real AMI, snapshot, launch-template, and instance identifiers

### Step 5: Rank remediation
- Remove public or external sharing first
- Then fix backing-snapshot exposure
- Then enforce IMDSv2 and image pipeline hygiene

### Step 6: Write narrative and quick wins
- Narrative should lead with the broadest image exposure or fleet-wide weak default
- Quick wins should prefer permission removal over long migration tasks

---

## 9. Remediation Playbooks

### Playbook: Remove Broad AMI Sharing
1. Inventory public and cross-account shared images
2. Remove public launch permissions immediately
3. Remove unnecessary external account permissions
4. Revalidate any org-approved golden-image sharing

### Playbook: Secure Backing Snapshots
1. Map each AMI to its backing snapshots
2. Remove public or unnecessary external sharing from those snapshots
3. Rebuild images on encrypted private snapshots where needed
4. Review historical copies and derivative images

### Playbook: Harden Image Defaults
1. Enforce IMDSv2 at the image level
2. Update launch templates and ASGs to the hardened image
3. Validate instance-level metadata settings do not override the hardening

### Playbook: Retire Stale Images Safely
1. Identify images with no active usage
2. Validate rollback requirements
3. Deprecate or deregister stale images
4. Clean up backing snapshots when retention is no longer required

---

## 10. Output Guidance

### Finding output
- Refer to actual **AMI IDs, snapshot IDs, instance IDs, launch template IDs, and ASG names**
- State whether the image is public/shared, whether its backing snapshots are exposed, and whether the image is actively used
- Distinguish between **external image distribution risk**, **backing-data exposure**, and **unsafe launch defaults**
- Use concise impact language focused on what outsiders can launch, restore, or inherit

### Attack path output
- `full_path_summary` should look like `ami-0123 -> external-account -> cloned-stack` or `ami-0123 -> snap-0456 -> offline-restore`
- Each `INFERRED` hop must explain what additional data would confirm it
- `remediation_priority` should begin with removing sharing, then fixing backing snapshots or fleet defaults

---

## 11. Minimum AMI Coverage Checklist

A thorough AMI analysis must evaluate:

### Direct AMI findings:
- [ ] Public AMIs
- [ ] Cross-account shared AMIs
- [ ] Public backing snapshots
- [ ] Unencrypted backing snapshots
- [ ] IMDSv2 not required
- [ ] Deregistration protection on critical images
- [ ] Old unused images
- [ ] Old images still driving active fleets

### Attack path evaluation (using dependency context):
- [ ] Public AMI clone of internal stack (AP-REF-01)
- [ ] Cross-account shared AMI path (AP-REF-02)
- [ ] Public AMI + public backing snapshot (AP-REF-03)
- [ ] Shared AMI + unencrypted backing snapshot (AP-REF-04)
- [ ] Golden AMI without IMDSv2 in fleet usage (AP-REF-05)
- [ ] Public internal image in active use (AP-REF-06)
- [ ] Shared AMI feeding Auto Scaling fleet (AP-REF-07)

If these are not evaluated, the AMI analysis is incomplete.
