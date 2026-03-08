# VPC Security Analysis Skill — Attack Path Edition

## Service Overview

VPC defines network segmentation, routing intent, and reachability boundaries across the AWS account. VPC findings should not be treated as isolated configuration issues. The real question is whether the network design creates unintended reachability, weak segmentation, poor visibility, or easy lateral movement after compromise.

This skill is designed for the **primary-service + dependency-context model** defined in CLAUDE.md. The VPC scanner Python file runs AWS CLI commands for VPC (primary) plus minimal dependency context from EC2, IAM, and other services. This skill tells CloudSentinel how to interpret all of that input and produce evidence-based findings and attack paths.

This skill should reason about VPCs as architecture, not just as resource lists.

Primary goals:
1. Identify unintended internet exposure
2. Distinguish public, private, and isolated subnet intent
3. Evaluate routing and egress paths
4. Check whether network traffic is observable
5. Assess whether compromise in one zone can spread to others

---

## 1. Input Layout and Interpretation

The VPC scanner Python file runs AWS CLI commands and delivers output in this structure:

```text
=== PRIMARY SERVICE: VPC ===
--- Command: describe-vpcs ---
[output]
--- Command: describe-subnets ---
[output]
--- Command: describe-route-tables ---
[output]
--- Command: describe-network-acls ---
[output]
--- Command: describe-internet-gateways ---
[output]
--- Command: describe-nat-gateways ---
[output]
--- Command: describe-vpc-endpoints ---
[output]
--- Command: describe-vpc-peering-connections ---
[output]
--- Command: describe-flow-logs ---
[output]
--- Command: describe-egress-only-internet-gateways ---
[output]
--- Command: describe-transit-gateway-attachments ---
[output]
--- Command: describe-vpc-endpoint-services ---
[output]

=== DEPENDENCY CONTEXT: EC2 ===
--- Command: describe-instances (instances per VPC/subnet, public IPs, instance profiles) ---
[output]
--- Command: describe-security-groups (SG rules per VPC) ---
[output]
--- Command: describe-network-interfaces (ENIs, attachment state, public IPs) ---
[output]

=== DEPENDENCY CONTEXT: IAM ===
--- Command: list-instance-profiles ---
[output]
--- Command: get-role (per role attached to instances in scanned VPCs) ---
[output]

=== DEPENDENCY CONTEXT: RDS ===
--- Command: describe-db-instances (database instances in scanned VPCs, public accessibility) ---
[output]

=== DEPENDENCY CONTEXT: ELB ===
--- Command: describe-load-balancers (ALBs/NLBs in scanned VPCs, schemes, subnets) ---
[output]
```

### Input Interpretation Rules

1. **PRIMARY SERVICE: VPC** is the full audit scope. Every VPC, subnet, route table, NACL, gateway, endpoint, and peering connection must be analyzed.
2. **DEPENDENCY CONTEXT** sections are supporting evidence only. Use them to understand what workloads exist in each VPC/subnet and whether the network design matters in practice.
3. Do NOT perform a standalone EC2, IAM, RDS, or ELB audit from dependency context.
4. Do NOT emit findings for dependency services unless a dependency misconfiguration is directly required to explain a VPC-centered attack path.
5. If a dependency section is missing or empty, do not assume it is secure or insecure. State what could not be evaluated.
6. Do NOT invent resources, instance IDs, SG rules, or database configurations not visible in the input.

### Output Contract Guardrails

- Return **valid JSON only**. Do not emit markdown fences or prose outside the JSON object.
- `findings[].severity` must always be one of `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.
- If evidence is ambiguous, keep the best-fit severity and set `findings[].status` to `NEEDS_REVIEW`. Never use `NEEDS_REVIEW` as a severity.
- `quick_wins[]` entries must include `finding_id`, `action`, `effort`, and `impact`.
- `attack_paths[].id` must use `AP-{NUMBER}`, and every `full_path_summary` must use real VPC, subnet, route table, NACL, or gateway identifiers from the scan.

---

## 2. Relationship Mapping (Do This First)

Before generating any findings or attack paths, build these maps from the scan data:

### VPC Resource Maps
- **VPC → Default or Custom**: whether each VPC is `IsDefault: true`
- **VPC → Flow Log Coverage**: whether flow logs exist for each VPC
- **VPC → Subnets**: all subnets per VPC
- **VPC → Internet Gateways**: IGW attachments per VPC
- **VPC → NAT Gateways**: NAT gateway placements per VPC
- **VPC → Endpoints**: VPC endpoints per VPC (gateway and interface)
- **VPC → Peering Connections**: active peering connections per VPC

### Subnet Classification (Use Route Tables as Source of Truth)
- **Subnet → Route Table**: which route table is associated (explicit or main)
- **Subnet → Classification**:
  - **Public**: default route (`0.0.0.0/0` or `::/0`) to `igw-*`
  - **Private**: default route to `nat-*` or no internet route
  - **Isolated**: no default internet route at all
- **Subnet → MapPublicIpOnLaunch**: auto-assign public IP setting
- **Subnet → Tags/Name**: intended purpose from naming (public, private, app, db, mgmt, etc.)
- **Subnet → Intent Match**: compare route-based classification to name/tag intent

### Network Control Maps
- **NACL → Subnets**: which NACLs are associated with which subnets
- **NACL → Rule Analysis**: whether NACLs provide meaningful segmentation or are effectively allow-all
- **Peering → Direction and Scope**: same-account vs cross-account, accepted status, route scopes

### Dependency Maps (from dependency context)
- **EC2 Instances per Subnet**: which instances are running where, public IPs, instance profiles
- **Security Groups per VPC**: SG rules showing actual port exposure
- **RDS Instances per Subnet**: database instances, public accessibility flags
- **Load Balancers per Subnet**: internet-facing vs internal schemes
- **IAM Roles on Instances**: what roles are attached to instances in each subnet

### Derived Relationships
- **Active VPCs**: VPCs with running instances, ENIs, load balancers, or RDS instances
- **Sensitive Subnets**: subnets tagged/named for db, mgmt, admin, backup, security, or containing RDS instances
- **Intent Mismatches**: subnets named "private" but routed to IGW
- **Blind Spots**: active VPCs without flow logs

---

## 3. Network Classification Logic

### Determine Subnet Type (Route Tables First)
Use route tables as the source of truth:
- **Public subnet**: default route to IGW or equivalent direct internet path
- **Private subnet**: default route to NAT gateway/instance but not to IGW
- **Isolated subnet**: no default internet route

### Determine Exposure Context
Increase concern if subnet or attached resources appear to be:
- prod / production
- db / database
- mgmt / admin / bastion
- backup / archive
- security tooling
- internal-only applications

### Determine Activity Level
Raise severity when VPC/subnet has (from dependency context):
- Running instances
- Active ENIs
- Load balancers
- RDS instances
- EKS/ECS context if visible through tags

Lower severity for empty or clearly dormant networks.

---

## 4. VPC Direct Findings — Misconfiguration Patterns

These are direct findings in the primary VPC service. Each pattern produces a `findings[]` entry.

### Pattern VPC-FLOWLOG-DISABLED: VPC Flow Logs Disabled on Active VPC
- **Detection**: No flow logs for a VPC that has workloads (confirmed via dependency context or subnet/ENI presence)
- **Category**: `logging_monitoring`
- **Base severity**: HIGH
- **Severity modifiers**:
  - VPC is empty or clearly non-production → MEDIUM
  - VPC hosts sensitive tiers AND has broad network exposure → CRITICAL
- **Impact**: Weak visibility for incident response, traffic analysis, and exfiltration/lateral-movement investigation
- **Fix**: Enable flow logs to CloudWatch Logs or S3 with correct IAM role and retention
- **Attack path role**: Amplifies all attack paths — compromise and movement go undetected

### Pattern VPC-DEFAULT-IN-USE: Default VPC Used for Real Workloads
- **Detection**: `IsDefault: true` with attached subnets/resources in use (from dependency context)
- **Category**: `resource_hygiene`
- **Base severity**: MEDIUM
- **Severity modifiers**: Raise to HIGH if sensitive/production workloads run there, especially with public IP auto-assign
- **Impact**: Default VPCs make accidental exposure easier and often indicate weak segmentation design
- **Fix**: Migrate to purpose-built VPC architecture and retire default VPC usage

### Pattern VPC-SUBNET-AUTO-PUBLIC: Subnet Auto-Assigns Public IP Unexpectedly
- **Detection**: `MapPublicIpOnLaunch: true`
- **Category**: `network_exposure`
- **Base severity**: MEDIUM
- **Severity modifiers**:
  - Subnet is tagged/named private, internal, app, db, mgmt, or prod-sensitive → HIGH
  - Subnet is clearly intended as a public web tier → LOW
- **Impact**: New instances may become publicly addressable by default
- **Fix**: `aws ec2 modify-subnet-attribute --subnet-id {subnet-id} --no-map-public-ip-on-launch`
- **Attack path role**: Creates unintended internet exposure for new workloads

### Pattern VPC-PRIVATE-IGW-ROUTE: IGW Route on Supposedly Private Subnet
- **Detection**: Subnet named/tagged private/internal but associated route table has `0.0.0.0/0` to `igw-*`
- **Category**: `network_exposure`
- **Base severity**: HIGH
- **Severity modifiers**: Raise to CRITICAL if subnet hosts db/admin/sensitive workloads AND SG context is broad
- **Impact**: Segmentation intent is broken — private workloads can be directly internet-reachable if other controls fail
- **Fix**: Replace IGW route with NAT or remove default internet route entirely
- **Attack path role**: Core misclassification that enables unexpected exposure

### Pattern VPC-NACL-ALLOW-ALL: Broad Allow-All NACL on Active Subnet
- **Detection**: NACL rules broadly allow all traffic from/to `0.0.0.0/0` with permissive low rule numbers
- **Category**: `network_exposure`
- **Base severity**:
  - HIGH on sensitive/active subnets
  - MEDIUM on routine public tiers
  - LOW on empty networks
- **Impact**: NACL layer offers little or no containment, leaving SGs as the only effective control
- **Fix**: Create targeted allows and explicit deny posture where architecture requires segmentation
- **Note**: Default allow-all NACLs are common; the key issue is whether stronger segmentation was expected but missing
- **Attack path role**: Removes a network defense layer, amplifying SG misconfigurations

### Pattern VPC-NO-ENDPOINTS: Missing VPC Endpoints for High-Use AWS Services
- **Detection**: No S3/DynamoDB endpoints in VPCs that appear to use those services
- **Category**: `network_exposure`
- **Base severity**: MEDIUM
- **Severity modifiers**: Raise to HIGH if security-sensitive workloads move large traffic through NAT/internet path
- **Impact**: Private workloads rely on public/NAT paths for AWS service access, increasing cost and external path exposure
- **Fix**: Deploy gateway or interface endpoints with restrictive policies
- **Note**: Both security and cost hygiene, not a critical exposure by itself

### Pattern VPC-ENDPOINT-BROAD-POLICY: Endpoint Policy Too Broad
- **Detection**: Interface/gateway endpoint exists but policy allows overly broad principals/actions/resources
- **Category**: `access_control`
- **Base severity**: MEDIUM or HIGH depending on exposed service/data sensitivity
- **Impact**: Private path exists but policy does not meaningfully constrain use
- **Fix**: Scope endpoint policy to approved principals, buckets, prefixes, or actions

### Pattern VPC-IGW-UNUSED: Unused Internet Gateway
- **Detection**: IGW exists but is not attached to a VPC or attached VPC has no subnets using it
- **Category**: `resource_hygiene`
- **Base severity**: LOW
- **Impact**: Mostly hygiene; can become accidental exposure later
- **Fix**: Remove unused IGW after dependency validation

### Pattern VPC-NAT-UNUSED: Unused NAT Gateway
- **Detection**: NAT gateway exists but no route tables reference it
- **Category**: `cost`
- **Base severity**: MEDIUM (cost concern — NAT gateways are expensive)
- **Fix**: Remove unused NAT gateway after dependency validation

### Pattern VPC-PEERING-CROSS-ACCOUNT: Cross-Account VPC Peering
- **Detection**: Peering connection owner IDs differ from requester/accepter
- **Category**: `network_exposure`
- **Base severity**: MEDIUM
- **Status rule**: Use `NEEDS_REVIEW` until the business need, reachable scope, and filtering controls are validated from scan evidence or operator context.
- **Severity modifiers**:
  - Peering reaches sensitive subnets or segmentation controls are weak → HIGH
  - Peer can reach security/admin/db tiers with minimal filtering → CRITICAL
- **Impact**: Creates trust path between accounts; if peer is compromised, this network may be reachable
- **Fix**: Validate business need, narrow routes, add subnet/NACL/SG segmentation

### Pattern VPC-PEERING-BROAD-ROUTES: Overly Broad Peering Routes
- **Detection**: Large CIDR routes to peering connection covering many subnets or sensitive ranges
- **Category**: `network_exposure`
- **Base severity**: HIGH
- **Impact**: Blast radius from peer compromise is wide
- **Fix**: Narrow route scopes and isolate sensitive subnets from peer-reachable ranges

### Pattern VPC-NO-SEGMENTATION: No Meaningful Segmentation Between Tiers
- **Detection**: Public, app, and db subnets share broad routing/NACL posture with little evidence of network separation
- **Category**: `network_exposure`
- **Base severity**: HIGH
- **Severity modifiers**: Raise to CRITICAL if sensitive production tiers appear reachable from internet-facing zones AND visibility is poor
- **Impact**: Attacker foothold in one tier can spread laterally without network barriers
- **Fix**: Redesign subnet/route/NACL boundaries and tighten east-west controls
- **Attack path role**: Enables lateral movement from any compromised instance

### Pattern VPC-IPV6-UNCONTROLLED: Internet-Reachable IPv6 Path Not Considered
- **Detection**: `::/0` route to IGW or egress path with weak matching NACL/SG controls
- **Category**: `network_exposure`
- **Base severity**: HIGH if workloads are IPv6-addressable and sensitive
- **Impact**: Teams sometimes secure IPv4 and forget IPv6 exposure
- **Fix**: Review IPv6 route intent and ensure SG/NACL controls match IPv4 hardening

---

## 5. VPC Attack Path Reference Catalog

These are the **reference attack paths** that CloudSentinel should attempt to match against actual scan evidence. A path from this catalog may ONLY be emitted as a formal `attack_paths[]` entry if it meets the evidence threshold from CLAUDE.md:

- At least **2 CONFIRMED hops**
- No more than **1 critical unexplained inference**
- Path is specific to actual resources found in the scan

---

### AP-REF-01: Broken Private Subnet → Unintended Internet Exposure of Sensitive Workloads

**Pattern**: "Private" Subnet with IGW Route → Public IP Auto-Assign → Sensitive Instance Exposed

**Chain hops**:
1. **Misclassification**: Subnet named/tagged private or internal but route table has `0.0.0.0/0` to IGW
2. **Public IP Assignment**: Subnet has `MapPublicIpOnLaunch: true` OR instances have public IPs
3. **Sensitive Workloads**: Instances in the subnet are running with sensitive tags/roles (from EC2 dependency context)
4. **Broad SG**: Security groups on those instances allow inbound from `0.0.0.0/0` (from EC2 dependency context)

**Evidence requirements**:
- Hop 1 CONFIRMED: route table analysis shows IGW route + subnet naming indicates private intent
- Hop 2 CONFIRMED: `MapPublicIpOnLaunch` in scan OR instances with public IPs in dependency context
- Hop 3 CONFIRMED if EC2 dependency context shows running instances with sensitive tags/roles; INFERRED if instances exist but tags are ambiguous
- Hop 4 CONFIRMED if EC2 dependency context shows open SG rules; INFERRED if SG data not available

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED.

**Impact**: Workloads intended to be private are directly internet-reachable. If those workloads include databases, admin tools, or sensitive applications, attackers can reach them directly from the internet.

**Remediation priority**:
1. Replace IGW route with NAT or remove default internet route
2. Disable public IP auto-assign on the subnet
3. Review and tighten SG rules on affected instances

---

### AP-REF-02: Public Subnet + Auto-Assign Public IP + Broad SG = Default Internet Exposure

**Pattern**: Public Subnet → Auto Public IP → Broad SG → Every New Instance Internet-Reachable

**Chain hops**:
1. **Public Subnet**: Route table has `0.0.0.0/0` to IGW
2. **Auto-Assign**: `MapPublicIpOnLaunch: true`
3. **Broad SG**: Default or widely-used SG in the VPC allows inbound from `0.0.0.0/0` on sensitive ports (from EC2 dependency context)
4. **New Instance Risk**: Any new instance launched in this subnet inherits internet exposure automatically

**Evidence requirements**:
- Hop 1 CONFIRMED: route table analysis in scan
- Hop 2 CONFIRMED: subnet attribute in scan
- Hop 3 CONFIRMED if EC2 dependency context shows broad SG rules; INFERRED if SG data not available
- Hop 4 INFERRED: future instance behavior is inherently inferential

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED, plus Hop 3.

**Impact**: The combination of public routing, auto-assign public IP, and broad SG means every new instance launched in this subnet is immediately internet-reachable on sensitive ports without any explicit action by the deployer.

**Remediation priority**:
1. Disable auto-assign public IP on the subnet
2. Tighten SG rules to restrict inbound to required sources
3. Review whether the subnet should be public at all

---

### AP-REF-03: No Flow Logs + Broad NACL + Active Workloads = Blind Lateral Movement

**Pattern**: Active VPC → No Flow Logs → Allow-All NACL → Compromise and Movement Undetectable

**Chain hops**:
1. **Active VPC**: VPC has running workloads (from dependency context)
2. **No Flow Logs**: No flow log configuration for this VPC
3. **Broad NACL**: NACLs are allow-all or near allow-all
4. **Broad SG**: Security groups allow broad internal communication (from EC2 dependency context)

**Evidence requirements**:
- Hop 1 CONFIRMED: dependency context shows running instances/ENIs in the VPC
- Hop 2 CONFIRMED: flow log absence confirmed in primary VPC scan
- Hop 3 CONFIRMED: NACL rule analysis in primary VPC scan shows allow-all posture
- Hop 4 CONFIRMED if EC2 dependency context shows broad SG rules; INFERRED if SG data not available

**Minimum for formal path**: Hops 1, 2, and 3 must be CONFIRMED.

**Impact**: An attacker who compromises any instance in the VPC can move laterally to other instances without network-level barriers and without detection. Incident response is severely hampered because no traffic logs exist.

**Remediation priority**:
1. Enable VPC flow logs immediately
2. Review and tighten NACLs to provide meaningful segmentation
3. Tighten SG rules to restrict east-west traffic

---

### AP-REF-04: Cross-Account Peering + Broad Routes + Weak Segmentation

**Pattern**: Cross-Account Peering → Broad Routes → Sensitive Subnet Reachable from Peer

**Chain hops**:
1. **Cross-Account Peering**: Active peering connection with different owner account
2. **Broad Routes**: Route table has broad CIDR routes to the peering connection covering sensitive subnets
3. **Weak NACL**: NACLs on sensitive subnets do not restrict peering traffic
4. **Sensitive Target**: Sensitive workloads (db, admin, security) exist in the reachable subnets (from dependency context)

**Evidence requirements**:
- Hop 1 CONFIRMED: peering connection in scan shows different owner account IDs + accepted status
- Hop 2 CONFIRMED: route table analysis shows broad routes to peering connection
- Hop 3 CONFIRMED: NACL analysis shows no meaningful restriction on peering traffic
- Hop 4 CONFIRMED if dependency context shows sensitive instances/databases in target subnets; INFERRED if subnets have sensitive names but workload details not available

**Minimum for formal path**: Hops 1, 2, and 3 must be CONFIRMED.

**Impact**: If the peer account is compromised, attackers can reach sensitive subnets in this account through the peering connection. Databases, admin tools, and internal services may be directly accessible across the peering path.

**Remediation priority**:
1. Narrow peering routes to specific, required CIDR ranges
2. Add NACL rules to restrict peering traffic to specific ports/sources
3. Validate whether the peering connection is still needed
4. Ensure sensitive subnets are not routable from the peering connection

---

### AP-REF-05: Default VPC + Production Workloads + Weak Controls

**Pattern**: Default VPC → Production Instances → Public Subnets → Weak SG/NACL → Insecure by Default

**Chain hops**:
1. **Default VPC**: VPC is the default VPC (`IsDefault: true`)
2. **Production Workloads**: Running instances with production tags or sensitive roles (from dependency context)
3. **Public Subnets**: Default VPC subnets have IGW routes and `MapPublicIpOnLaunch: true`
4. **Weak Controls**: No flow logs, allow-all NACLs, and broad SGs

**Evidence requirements**:
- Hop 1 CONFIRMED: VPC `IsDefault: true` in scan
- Hop 2 CONFIRMED if dependency context shows production-tagged instances; INFERRED if instances exist but tags unclear
- Hop 3 CONFIRMED: route table and subnet attributes in scan
- Hop 4 CONFIRMED: flow log + NACL + SG analysis from scan and dependency context

**Minimum for formal path**: Hops 1 and 3 must be CONFIRMED, plus either Hop 2 or Hop 4.

**Impact**: Production workloads running in a default VPC inherit insecure-by-convenience network design. Public subnets with auto-assign IPs and broad controls mean any deployed workload is immediately exposed.

**Remediation priority**:
1. Migrate production workloads to a purpose-built VPC
2. Disable auto-assign public IP on default VPC subnets as an interim measure
3. Enable flow logs on the default VPC
4. Tighten SGs and NACLs

---

### AP-REF-06: No Segmentation Between Web and Database Tiers

**Pattern**: Internet-Facing Subnet → Flat Network → Database Subnet → Direct DB Access After Web Compromise

**Chain hops**:
1. **Web Tier**: Internet-facing subnet with web-serving instances (from dependency context)
2. **Flat Network**: No meaningful NACL or route table separation between web and database subnets
3. **Database Tier**: Subnet containing RDS instances or database-tagged EC2 instances (from dependency context)
4. **Direct Path**: An attacker who compromises a web instance can reach database instances on database ports

**Evidence requirements**:
- Hop 1 CONFIRMED: route table shows IGW route + dependency context shows web-serving instances
- Hop 2 CONFIRMED: NACL analysis shows allow-all between web and db subnets + shared or open route posture
- Hop 3 CONFIRMED if dependency context shows RDS instances or database-tagged EC2 in the subnet; INFERRED if subnet names suggest db but no workload confirmation
- Hop 4 CONFIRMED if EC2/RDS dependency context shows SG rules allow database port access from web subnet; INFERRED if SG data not available

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED, plus Hop 3.

**Impact**: A web application compromise provides a direct network path to database instances. Without segmentation, there is no network-level barrier preventing lateral movement from the web tier to the data tier.

**Remediation priority**:
1. Create dedicated NACLs for database subnets restricting inbound to application ports from app-tier CIDRs only
2. Ensure database SGs only allow connections from application SGs, not from web-tier or broad CIDRs
3. Consider moving databases to isolated subnets with no internet route

---

### AP-REF-07: Transit/Peering Hub with Weak Filtering → Multi-VPC Blast Radius

**Pattern**: Transit Gateway/Peering Hub → Multiple VPCs Reachable → Compromise Spreads Across VPCs

**Chain hops**:
1. **Hub Connectivity**: Transit gateway attachments or multiple peering connections create a hub topology
2. **Broad Routing**: Routes between VPCs cover broad CIDR ranges
3. **Weak Filtering**: NACLs and SGs do not restrict inter-VPC traffic
4. **Multi-VPC Impact**: Compromise in one VPC can reach workloads in other VPCs

**Evidence requirements**:
- Hop 1 CONFIRMED: transit gateway attachments or multiple peering connections in scan
- Hop 2 CONFIRMED: route table analysis shows broad cross-VPC routes
- Hop 3 CONFIRMED: NACL analysis shows no meaningful restriction on cross-VPC traffic
- Hop 4 INFERRED: multi-VPC impact depends on what workloads exist in each VPC

**Minimum for formal path**: Hops 1, 2, and 3 must be CONFIRMED.

**Impact**: A compromise in one VPC can spread to other connected VPCs through the transit/peering hub. The blast radius of any single-VPC breach becomes multi-VPC.

**Remediation priority**:
1. Narrow cross-VPC routes to specific required ranges
2. Implement NACL segmentation at VPC boundaries
3. Use transit gateway route table segmentation
4. Enable flow logs on all connected VPCs

---

### AP-REF-08: IPv6 Exposure Bypass

**Pattern**: IPv4 Hardened → IPv6 Route to IGW → IPv6-Addressable Instance Exposed

**Chain hops**:
1. **IPv4 Secure**: Subnet has no IPv4 IGW route or instances lack IPv4 public IPs
2. **IPv6 Route**: Route table has `::/0` route to IGW or egress-only IGW
3. **IPv6 Addressable**: Instances have IPv6 addresses (from dependency context)
4. **Weak IPv6 Controls**: NACLs and SGs do not restrict IPv6 traffic equivalently to IPv4

**Evidence requirements**:
- Hop 1 CONFIRMED: IPv4 route analysis in scan (establishes false sense of security)
- Hop 2 CONFIRMED: IPv6 route to IGW in route table
- Hop 3 CONFIRMED if dependency context shows instances with IPv6 addresses; INFERRED if IPv6 enabled on subnet but instance details unavailable
- Hop 4 CONFIRMED if NACL/SG analysis shows IPv6 rules are weaker than IPv4; INFERRED if IPv6 rules not explicitly visible

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED, plus Hop 3 or Hop 4.

**Impact**: Teams that hardened IPv4 access paths may have overlooked IPv6. Instances that appear private over IPv4 may be directly reachable over IPv6.

**Remediation priority**:
1. Ensure IPv6 SG and NACL rules match IPv4 hardening
2. Remove IPv6 IGW route if not required
3. Disable IPv6 on subnets that don't need it

---

### AP-REF-09: Database in Public Subnet

**Pattern**: Public Subnet → RDS Instance with Public Accessibility → Direct Database Exposure

**Chain hops**:
1. **Public Subnet**: Subnet route table has `0.0.0.0/0` to IGW
2. **Database Placement**: RDS instance or database EC2 instance in the public subnet (from dependency context)
3. **Public Accessibility**: RDS `PubliclyAccessible: true` or EC2 instance has public IP
4. **Broad SG**: Security group allows database port from `0.0.0.0/0` (from dependency context)

**Evidence requirements**:
- Hop 1 CONFIRMED: route table analysis in scan
- Hop 2 CONFIRMED: RDS or EC2 dependency context shows database in this subnet
- Hop 3 CONFIRMED: RDS `PubliclyAccessible` flag or EC2 public IP in dependency context
- Hop 4 CONFIRMED if EC2 dependency context shows SG allows database port from internet; INFERRED if SG data unavailable

**Minimum for formal path**: Hops 1, 2, and 3 must be CONFIRMED.

**Impact**: Database is directly accessible from the internet. Attackers can attempt credential brute force, exploit database vulnerabilities, or exfiltrate data.

**Remediation priority**:
1. Move database to a private subnet
2. Disable `PubliclyAccessible` on RDS instances
3. Restrict SG to allow database port only from application-tier instances

---

### AP-REF-10: VPC Endpoint Abuse via Broad Policy

**Pattern**: VPC Endpoint → Broad Policy → Unauthorized Service Access via Private Path

**Chain hops**:
1. **Endpoint Exists**: VPC endpoint for S3, DynamoDB, or other service exists
2. **Broad Policy**: Endpoint policy allows `*` principal or `*` action or `*` resource
3. **Unauthorized Access**: Any principal in the VPC can access the service through the endpoint without restriction
4. **Sensitive Service**: The endpoint connects to a service with sensitive data (e.g., S3 buckets with production data)

**Evidence requirements**:
- Hop 1 CONFIRMED: endpoint configuration in scan
- Hop 2 CONFIRMED: endpoint policy analysis shows broad permissions
- Hop 3 INFERRED: unauthorized access depends on what principals exist in the VPC
- Hop 4 CONFIRMED if dependency context or service context confirms sensitive data; INFERRED if not available

**Minimum for formal path**: Hops 1 and 2 must be CONFIRMED plus at least one additional confirmed hop.

**Impact**: The private endpoint path bypasses internet-based controls, and the broad policy means any compromised instance in the VPC can access the service without restriction.

**Remediation priority**:
1. Scope endpoint policy to specific principals and resources
2. Add S3 bucket policies that restrict access to the endpoint
3. Monitor endpoint traffic via flow logs

---

### AP-REF-11: NAT Gateway as Sole Egress Control + No Flow Logs

**Pattern**: Private Subnet → NAT Gateway → Unrestricted Outbound → No Flow Logs → Undetected Exfiltration

**Chain hops**:
1. **Private Subnet**: Subnet is private (NAT route, no IGW)
2. **NAT Egress**: All outbound internet traffic goes through NAT gateway
3. **No Outbound Restriction**: NACLs and SGs allow all outbound traffic
4. **No Flow Logs**: VPC flow logs not enabled

**Evidence requirements**:
- Hop 1 CONFIRMED: route table analysis shows NAT route
- Hop 2 CONFIRMED: NAT gateway exists and is referenced by route
- Hop 3 CONFIRMED: NACL outbound allows all + SG outbound allows all (from primary scan and dependency context)
- Hop 4 CONFIRMED: no flow logs for this VPC

**Minimum for formal path**: Hops 1, 2, 3, and 4 should all be CONFIRMED for a strong path. Minimum: Hops 2 and 4 CONFIRMED.

**Impact**: A compromised instance in the private subnet can exfiltrate data to any internet endpoint through the NAT gateway without detection. NAT provides egress but no filtering or monitoring.

**Remediation priority**:
1. Enable VPC flow logs immediately
2. Add outbound NACL restrictions or SG egress rules limiting traffic to required destinations
3. Consider VPC endpoints to reduce NAT dependence for AWS service access

---

### AP-REF-12: Peering with Sensitive Subnet Reachability + Stale Connection

**Pattern**: Stale or Unused Peering → Still Active Routes → Sensitive Subnets Reachable → Unnecessary Attack Surface

**Chain hops**:
1. **Peering Connection**: Active peering connection exists
2. **No Active Traffic**: Peering appears unused or stale (no recent workload justification visible)
3. **Active Routes**: Route table still has routes to the peering connection covering sensitive subnets
4. **Sensitive Targets**: Sensitive subnets are reachable through the peering connection

**Evidence requirements**:
- Hop 1 CONFIRMED: peering connection in scan with `active` status
- Hop 2 INFERRED: staleness is inferred from absence of workload justification (cannot confirm from network scan alone)
- Hop 3 CONFIRMED: route table shows routes to peering connection
- Hop 4 CONFIRMED if sensitive subnets are within the routed CIDR range

**Minimum for formal path**: Hops 1, 3, and 4 must be CONFIRMED.

**Impact**: An unused peering connection that still has active routes creates unnecessary attack surface. If the peer account is compromised, sensitive subnets remain reachable for no operational reason.

**Remediation priority**:
1. Validate whether the peering connection is still needed
2. Remove routes to the peering connection if not required
3. Delete the peering connection if confirmed unnecessary
4. Narrow routes to required ranges if still needed

---

## 6. False Positive and Context Controls

### Do NOT flag as findings by default:
- Public web-tier subnets intentionally routing to IGW
- NAT gateways in active private architectures
- Lack of VPC endpoints in tiny low-risk dev environments unless traffic profile suggests value
- Default NACL allow-all in simple environments where SGs are the primary control and no stronger segmentation intent exists

### Use NEEDS_REVIEW when:
- Cross-account peering may be legitimate organizational design
- Subnet naming/tags are unclear and route intent cannot be confidently inferred
- Endpoint broadness is visible but service/business dependency context is missing

### Lower severity when:
- VPC or subnet is empty / dormant
- Public behavior clearly matches a known internet-facing tier
- Controls are broad but compensating visibility and segmentation are strong

### Raise severity when:
- Production/sensitive tags appear
- Database, admin, backup, or security tooling subnets are exposed or poorly segmented
- Multiple misconfigurations exist on the same path from internet to internal resource
- Dependency context confirms sensitive workloads (RDS, admin instances) in affected subnets

---

## 7. Dependency Context Usage Rules (VPC Specific)

### You MAY:
- Use EC2 dependency context to confirm which instances run in which subnets, their public IPs, SG rules, and IAM roles
- Use RDS dependency context to confirm database placements and public accessibility
- Use ELB dependency context to confirm load balancer placements and internet-facing status
- Use IAM dependency context to understand what roles are attached to instances in sensitive subnets
- Reference dependency data in `attack_paths[].chain[]` hops and remediation steps

### You MUST NOT:
- Perform a standalone EC2 security audit (SG misconfigurations, IMDSv1, etc.) from dependency context
- Emit RDS findings (encryption, backup, etc.) as independent findings
- Treat dependency context as a full scan of that service
- Invent instance IDs, SG rules, RDS configurations, or IAM policies not in the input

### When dependency context is missing:
- Note in the `narrative` that workload-level impact could not be fully assessed
- Keep the VPC-direct finding (route misclassification, missing flow logs, etc.) and note that dependency context would strengthen the assessment
- Do NOT create formal attack paths with more than 1 unconfirmed inference

---

## 8. Attack Path Construction Workflow

Follow this order when analyzing VPC scan output:

### Step 1: Build relationship maps (Section 2)
Map all VPC resources, classify subnets, and identify intent mismatches. Map dependency context to understand what workloads exist where.

### Step 2: Reconstruct the architecture
Before producing findings, understand the overall network design:
1. How many VPCs? Default vs custom?
2. How are subnets classified? Public/private/isolated?
3. Where are the internet paths? IGW, NAT, peering, transit?
4. Where are the sensitive workloads?
5. Is there visibility (flow logs)?
6. Is there segmentation (NACLs, separate route tables)?

### Step 3: Identify direct findings (Section 4)
Walk through each misconfiguration pattern against the scan data. Emit `findings[]` entries for every confirmed issue.

### Step 4: Attempt attack path matching (Section 5)
For each intent mismatch, visibility gap, or segmentation weakness:
1. Check which reference attack paths (AP-REF-01 through AP-REF-12) could apply
2. For each candidate path, verify each hop against actual scan evidence
3. Label each hop as `CONFIRMED` or `INFERRED`
4. Count confirmed and inferred hops
5. If the path meets the evidence threshold (≥2 CONFIRMED, ≤1 critical unexplained inference), emit it as a formal `attack_paths[]` entry
6. If the path does NOT meet the threshold, keep relevant issues as normal findings

### Step 5: Cross-reference findings and paths
- Add `attack_path_ids` to any finding that participates in a formal attack path
- Ensure attack path `chain[]` references actual finding IDs

### Step 6: Rank remediation
- Prioritize fixes that break confirmed attack paths
- Prioritize visibility fixes (flow logs) — they improve all detection
- Prioritize segmentation fixes for sensitive tiers (db, admin, backup)
- Then address hygiene issues

### Step 7: Write narrative and quick wins
- Narrative must reference the most severe confirmed network path
- Quick wins should lead with flow logs and intent mismatch fixes

---

## 9. Remediation Playbooks

### Playbook: Fix Broken Private Subnet Design
1. Identify subnets labeled private/internal but routed to IGW
2. Move their default route to NAT if outbound internet is needed
3. Remove direct IGW path
4. Validate that no public IP auto-assign remains
5. Recheck SG and NACL containment

### Playbook: Improve Network Visibility
1. Enable flow logs on all active VPCs
2. Send logs to a central destination with retention and access control
3. Prioritize production and sensitive VPCs first
4. Validate log delivery role and coverage

### Playbook: Reduce Lateral Movement Risk
1. Identify broad NACLs, broad peering routes, and weak SG boundaries
2. Separate public, app, and data tiers clearly
3. Tighten route scopes and subnet accessibility
4. Apply stronger controls to db/admin/backup/security tiers

### Playbook: Reduce Internet Path Dependence
1. Identify private workloads using NAT/public paths for AWS services
2. Add VPC endpoints for S3/DynamoDB and critical interface endpoints
3. Restrict endpoint policies to intended usage
4. Reassess cost and traffic reduction

### Playbook: Secure Cross-Network Connectivity
1. Audit all peering connections and transit gateway attachments
2. Validate business need for each connection
3. Narrow routes to specific required CIDRs
4. Add NACL segmentation at network boundaries
5. Enable flow logs for cross-network visibility

---

## 10. Output Guidance

### Finding output
- Refer to actual **VPC, subnet, route table, NACL, gateway, and peering IDs** from the scan
- Explain whether the issue is **exposure**, **segmentation failure**, **visibility gap**, or **lateral-movement risk**
- Describe **real reachability**, not generic "network insecurity"
- Say whether the problem affects one subnet, one VPC, or multiple environments
- Use `NEEDS_REVIEW` when topology may be intentionally complex and data is incomplete

### Attack path output
- `full_path_summary` must use real resource IDs: `Internet → igw-0abc → rtb-0def → subnet-0123 (private-db) → i-0456 (db-prod)`
- Each `chain[]` hop must have `evidence_status` (`CONFIRMED` or `INFERRED`)
- Each `INFERRED` hop must explain why it is inferred and what data would confirm it
- `remediation_priority` must list the shortest path to break the chain

**Good finding example**:
> Subnet `subnet-0abc1234` is tagged "private-db" but its associated route table `rtb-0def5678` has a `0.0.0.0/0` route to `igw-0111`. Combined with `MapPublicIpOnLaunch: true`, this means any new instance in this supposedly private database subnet will be directly internet-reachable.

**Bad finding example**:
> The network may have security issues.

---

## 11. Minimum VPC Coverage Checklist

A thorough VPC analysis must evaluate:

### Direct VPC findings:
- [ ] Flow log coverage on active VPCs
- [ ] Default VPC usage for production workloads
- [ ] Subnet public IP auto-assign on non-public subnets
- [ ] IGW routes on subnets with private/internal intent
- [ ] NACL effectiveness (allow-all vs meaningful segmentation)
- [ ] Missing VPC endpoints for high-use AWS services
- [ ] Endpoint policy broadness
- [ ] Unused IGWs and NAT gateways
- [ ] Cross-account peering connections
- [ ] Broad peering routes
- [ ] Tier segmentation (web/app/db/admin separation)
- [ ] IPv6 exposure control
- [ ] Transit gateway and hub connectivity

### Attack path evaluation (using dependency context):
- [ ] Broken private subnet exposure (AP-REF-01)
- [ ] Public subnet auto-exposure (AP-REF-02)
- [ ] Blind lateral movement (AP-REF-03)
- [ ] Cross-account peering to sensitive subnets (AP-REF-04)
- [ ] Default VPC production risk (AP-REF-05)
- [ ] No segmentation between web and db tiers (AP-REF-06)
- [ ] Multi-VPC blast radius via transit/peering (AP-REF-07)
- [ ] IPv6 exposure bypass (AP-REF-08)
- [ ] Database in public subnet (AP-REF-09)
- [ ] VPC endpoint abuse (AP-REF-10)
- [ ] NAT egress without detection (AP-REF-11)
- [ ] Stale peering with sensitive reachability (AP-REF-12)

If these are not evaluated, the VPC analysis is incomplete.
