# ELB Security Analysis Skill - Attack Path Edition

## Service Overview

Load balancers are the exposure brokers for many AWS applications. ELB findings should not stop at "the listener is public." The important question is what the listener exposes, how traffic is protected, what targets sit behind it, and whether the load balancer turns a private backend into an externally reachable service.

This skill is designed for the **primary-service + dependency-context model** defined in `AGENTS.md` / `CLAUDE.md`. The ELB scanner Python file should collect ALB, NLB, and Classic ELB configuration plus minimal dependency context from EC2, WAF, ACM, and IAM. This skill tells CloudSentinel how to interpret that input and produce evidence-based findings and attack paths.

Primary goals:
1. Detect public listeners exposing admin, data, or sensitive backend ports
2. Evaluate listener security for HTTPS/TLS, certificates, and policy strength
3. Assess WAF, access logging, and deletion-protection posture
4. Map listener rules and target groups to real backend impact
5. Validate only evidence-backed exposure and pivot paths

---

## 1. Input Layout and Interpretation

The ELB scanner Python file should run AWS CLI commands and deliver output in this structure:

```text
=== PRIMARY SERVICE: ELB ===
--- Command: elbv2 describe-load-balancers ---
[output]
--- Command: elbv2 describe-listeners (per ALB/NLB) ---
[output]
--- Command: elbv2 describe-rules (per ALB listener) ---
[output]
--- Command: elbv2 describe-target-groups ---
[output]
--- Command: elbv2 describe-target-health (per target group) ---
[output]
--- Command: elbv2 describe-load-balancer-attributes (per ALB/NLB) ---
[output]
--- Command: elbv2 describe-target-group-attributes (per target group) ---
[output]
--- Command: elbv2 describe-tags (per load balancer / target group) ---
[output]
--- Command: elb describe-load-balancers ---
[output]
--- Command: elb describe-load-balancer-attributes (per Classic ELB) ---
[output]
--- Command: elb describe-load-balancer-policies (per Classic ELB listener policy) ---
[output]
--- Command: elb describe-tags (per Classic ELB) ---
[output]

=== DEPENDENCY CONTEXT: EC2 ===
--- Command: describe-security-groups (for ALB/CLB and target reachability context) ---
[output]
--- Command: describe-subnets ---
[output]
--- Command: describe-route-tables ---
[output]
--- Command: describe-instances (instance targets behind public load balancers) ---
[output]

=== DEPENDENCY CONTEXT: WAFV2 ===
--- Command: get-web-acl-for-resource (per ALB ARN) ---
[output]

=== DEPENDENCY CONTEXT: ACM ===
--- Command: describe-certificate (per listener certificate ARN) ---
[output]

=== DEPENDENCY CONTEXT: IAM ===
--- Command: list-instance-profiles ---
[output]
--- Command: get-role (per role attached to EC2 targets behind public load balancers) ---
[output]
--- Command: list-attached-role-policies (per target role) ---
[output]
--- Command: get-policy-version (per significant policy) ---
[output]
```

### Input Interpretation Rules

1. **PRIMARY SERVICE: ELB** is the full audit scope. Every ALB, NLB, target group, listener, rule, and Classic ELB configuration in this section must be analyzed.
2. **DEPENDENCY CONTEXT** sections are supporting evidence only. Use them to validate target exposure, WAF coverage, certificate state, and downstream IAM blast radius.
3. Do NOT perform a standalone EC2, ACM, WAF, or IAM audit from dependency context.
4. Do NOT emit findings for dependency services unless a dependency misconfiguration is directly required to explain an ELB-centered attack path.
5. If a dependency section is missing or empty, do not assume it is secure or insecure. State what could not be evaluated.
6. Do NOT invent application vulnerabilities, target behavior, or certificate details that are not visible in the scan.

### Output Contract Guardrails

- Return **valid JSON only**. Do not emit markdown fences or prose outside the JSON object.
- `findings[].severity` must always be one of `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.
- If evidence is ambiguous, keep the best-fit severity and set `findings[].status` to `NEEDS_REVIEW`.
- `quick_wins[]` entries must include `finding_id`, `action`, `effort`, and `impact`.
- `attack_paths[].id` must use `AP-{NUMBER}`, and every `full_path_summary` must use real load balancer names/ARNs, listeners, target groups, instance IDs, or SG IDs from the scan.

---

## 2. Relationship Mapping (Do This First)

Before generating any findings or attack paths, build these maps from the scan data:

### Load Balancer Resource Maps
- **LB -> Type and Scheme**: ALB, NLB, or Classic ELB; `internet-facing` vs `internal`
- **LB -> Subnets / VPC**: where the LB lives and whether the subnets are public
- **LB -> Listener Set**: protocols, ports, certificates, SSL/TLS policies
- **LB -> Rules**: listener rule conditions and forwarding actions
- **LB -> Target Groups**: protocol, port, target type, and health
- **LB -> Attributes**: access logs, deletion protection, HTTP hardening attributes where present
- **LB -> Tags**: sensitivity and business context indicators

### Dependency Maps (from dependency context)
- **LB -> Security Groups**: for ALB and Classic ELB, what inbound sources and ports are allowed
- **LB -> Public Subnet Intent**: whether the LB is actually in IGW-routed subnets
- **Target Group -> EC2 Targets**: which instances sit behind public listeners
- **Target EC2 -> IAM Role**: what cloud permissions those target instances carry
- **ALB -> WAF**: whether a web ACL is attached
- **Listener -> ACM Certificate**: certificate metadata where HTTPS/TLS exists

### Derived Relationships
- **Direct Internet Exposure**: internet-facing scheme + public subnet path + exposed listener
- **Sensitive Service Exposure**: public listener forwards to admin or data-service ports
- **Web-to-Cloud Pivot Path**: public ALB -> EC2 targets -> attached IAM role
- **Undetected Exposure**: public listener + access logs disabled
- **Weak Front Door**: public HTTP-only or outdated TLS policy

Always separate:
- **Public web serving that is expected**
- **Public exposure of sensitive services that is not**
- **Weak transport protection**
- **Backend blast radius after compromise**

---

## 3. ELB Direct Findings - Misconfiguration Patterns

These are direct findings in the primary ELB service. Each pattern produces a `findings[]` entry.

### Pattern ELB-PUBLIC-SENSITIVE-PORT: Internet-Facing Listener Exposes Admin or Data Port
- **Detection**: internet-facing ALB/NLB/CLB listener exposes ports such as 22, 3389, 3306, 5432, 1433, 1521, 2379, 9200, 5601, 8080 admin paths, or other clearly non-public service ports
- **Category**: `network_exposure`
- **Base severity**: CRITICAL
- **Impact**: The load balancer makes a sensitive backend service directly reachable from the internet.
- **Fix**: Restrict or remove the listener, move the service behind a private LB, or front it with stronger application controls
- **Attack path role**: Direct entry point for host or data-service compromise

### Pattern ELB-HTTP-ONLY: Internet-Facing Web Load Balancer Uses HTTP Without Strong HTTPS Enforcement
- **Detection**: public ALB or Classic ELB serves HTTP on port 80 without a proven HTTPS listener and redirect strategy
- **Category**: `access_control`
- **Base severity**: MEDIUM
- **Severity modifiers**:
  - Login, auth, admin, or customer-facing naming/tags -> HIGH
  - Public HTTPS exists and HTTP only redirects -> LOW or no finding
- **Impact**: Users and sessions may traverse the front door without strong transport protection.
- **Fix**: Add HTTPS/TLS listener and redirect HTTP to HTTPS
- **Attack path role**: Usually keep as a direct finding unless other evidence creates a stronger chain

### Pattern ELB-WEAK-TLS-POLICY: Public HTTPS/TLS Listener Uses Outdated Security Policy
- **Detection**: public HTTPS/TLS listener uses an outdated or weak SSL/TLS policy
- **Category**: `compliance`
- **Base severity**: HIGH
- **Status rule**: Use `NEEDS_REVIEW` if the policy name is visible but the exact cipher/TLS implications cannot be confidently mapped from the collected data.
- **Impact**: The public front door may permit weaker protocol versions or cipher suites than expected.
- **Fix**: `aws elbv2 modify-listener --listener-arn {listener-arn} --ssl-policy {modern-policy}`
- **Classic fix**: update the Classic ELB listener policy to a stronger TLS policy
- **Attack path role**: Weakens secure transport but is usually a direct finding unless paired with a stronger exposure chain

### Pattern ELB-NO-WAF: Public ALB Missing WAF Association
- **Detection**: internet-facing ALB with HTTP/HTTPS listeners has no WAF association in dependency context
- **Category**: `access_control`
- **Base severity**: MEDIUM
- **Status rule**: Use `NEEDS_REVIEW` when the ALB fronts a low-risk site or non-browser workload and the scan cannot confirm application risk.
- **Severity modifiers**:
  - Public admin or customer-facing application -> HIGH
- **Impact**: The web edge lacks a common application-layer filtering control.
- **Fix**: `aws wafv2 associate-web-acl --web-acl-arn {web-acl-arn} --resource-arn {lb-arn}`
- **Attack path role**: Amplifies public web-entry chains

### Pattern ELB-NO-ACCESS-LOGS: Access Logging Disabled on Public or Important Load Balancer
- **Detection**: access logs disabled on an internet-facing or important LB
- **Category**: `logging_monitoring`
- **Base severity**: MEDIUM
- **Severity modifiers**:
  - Internet-facing and sensitive -> HIGH
- **Impact**: Public traffic, abuse, and exploit attempts are harder to investigate.
- **Fix**: `aws elbv2 modify-load-balancer-attributes --load-balancer-arn {lb-arn} --attributes Key=access_logs.s3.enabled,Value=true Key=access_logs.s3.bucket,Value={log-bucket} Key=access_logs.s3.prefix,Value={prefix}`
- **Classic fix**: `aws elb modify-load-balancer-attributes --load-balancer-name {lb-name} --load-balancer-attributes AccessLog={Enabled=true,S3BucketName={log-bucket},EmitInterval=5,S3BucketPrefix={prefix}}`
- **Attack path role**: Makes exploitation harder to detect and investigate

### Pattern ELB-DELETION-PROTECTION-OFF: Deletion Protection Disabled on Important Load Balancer
- **Detection**: deletion protection disabled on a public or production LB
- **Category**: `resource_hygiene`
- **Base severity**: LOW
- **Severity modifiers**:
  - Public or production LB -> MEDIUM
- **Impact**: Important front-door infrastructure can be removed accidentally or maliciously more easily.
- **Fix**: `aws elbv2 modify-load-balancer-attributes --load-balancer-arn {lb-arn} --attributes Key=deletion_protection.enabled,Value=true`
- **Classic ELB note**: no direct equivalent; treat as applicable to ALB/NLB

### Pattern ELB-ALB-SG-BROAD-NONWEB: ALB / Classic ELB Security Group Broadly Open on Non-Web Ports
- **Detection**: SG attached to ALB or Classic ELB allows broad inbound from `0.0.0.0/0` or `::/0` on non-standard web ports that expose admin or backend services
- **Category**: `network_exposure`
- **Base severity**: HIGH
- **Severity modifiers**:
  - Listener also forwards that same sensitive port -> CRITICAL
- **Impact**: The edge allows direct internet traffic to services that should not be public.
- **Fix**: `aws elbv2 set-security-groups --load-balancer-arn {lb-arn} --security-groups {approved-sg-list}`
- **Classic fix**: `aws elb apply-security-groups-to-load-balancer --load-balancer-name {lb-name} --security-groups {approved-sg-list}`
- **Attack path role**: Entry point for sensitive-service exposure

### Pattern ELB-PUBLIC-TO-SENSITIVE-TARGET: Public Listener Forwards to Sensitive Backend Port or Admin Path
- **Detection**: listener rule or target group forwards public traffic to admin, database, or otherwise sensitive backend ports or paths
- **Category**: `network_exposure`
- **Base severity**: CRITICAL
- **Impact**: The load balancer turns a sensitive backend into a public service.
- **Fix**: Move the target behind a private LB or restrict the listener/rule to approved sources and paths
- **Attack path role**: Direct path from internet to sensitive backend

### Pattern ELB-HTTP-HARDENING-WEAK: HTTP Header / Desync Hardening Attributes Disabled
- **Detection**: ALB attributes show weak values for `routing.http.drop_invalid_header_fields.enabled` or desync mitigation where collected
- **Category**: `compliance`
- **Base severity**: LOW
- **Status rule**: Use `NEEDS_REVIEW` when the exact attribute set is incomplete.
- **Impact**: The public edge may be more permissive than necessary for malformed traffic or desync-style behavior.
- **Fix**: Update ALB attributes to stronger recommended values

---

## 4. ELB Attack Path Reference Catalog

These are the **reference attack paths** that CloudSentinel should attempt to match against actual scan evidence. A path from this catalog may ONLY be emitted as a formal `attack_paths[]` entry if it meets the evidence threshold from `AGENTS.md` / `CLAUDE.md`.

---

### AP-REF-01: Internet to Sensitive Backend Port Through Public Load Balancer

**Pattern**: Internet -> Public LB Listener -> Admin / Data Service Port

**Chain hops**:
1. **Entry**: load balancer is internet-facing
2. **Listener Exposure**: listener exposes a sensitive port
3. **Target**: target group or Classic ELB backend serves the sensitive service

**Evidence requirements**:
- Hop 1 CONFIRMED: scheme visible
- Hop 2 CONFIRMED: listener port and protocol visible
- Hop 3 CONFIRMED: target group or backend port mapping visible

**Minimum for formal path**: All three hops should be CONFIRMED.

**Impact**: The load balancer creates a direct external path to an administrative or data-bearing backend service.

**Remediation priority**:
1. Remove or restrict the public listener
2. Move the service behind a private LB if it must remain load balanced
3. Restrict backend SGs and target-group exposure

---

### AP-REF-02: Internet to Database Service via Public NLB / CLB

**Pattern**: Internet -> Public LB -> Database Port -> Direct Data Access Attempt

**Chain hops**:
1. **Entry**: LB is internet-facing
2. **DB Listener**: listener exposes a database port such as 3306, 5432, 1433, or 1521
3. **Database Target**: target group or backend indicates a database-style service

**Evidence requirements**:
- Hop 1 CONFIRMED: scheme visible
- Hop 2 CONFIRMED: listener port visible
- Hop 3 CONFIRMED: target port or target naming indicates database backend

**Minimum for formal path**: All three hops should be CONFIRMED.

**Impact**: The load balancer turns a database or database-like service into an internet-facing endpoint.

**Remediation priority**:
1. Remove public database listeners
2. Move the database behind private connectivity only
3. Restrict source access to app-tier or approved administrative networks

---

### AP-REF-03: Public ALB to EC2 Target to IAM Role Pivot

**Pattern**: Internet -> Public ALB -> EC2 Target -> IAM Role -> Cloud Access

**Chain hops**:
1. **Entry**: ALB is public and fronts a web-facing listener
2. **Target Path**: target group contains EC2 instances
3. **Target Compromise**: attacker gains code execution on the target application
4. **IAM Pivot**: target instance has an attached IAM role with meaningful cloud permissions

**Evidence requirements**:
- Hop 1 CONFIRMED: scheme and listener visible
- Hop 2 CONFIRMED: target group and EC2 instance targets visible
- Hop 3 INFERRED: application compromise is the attacker assumption
- Hop 4 CONFIRMED: IAM dependency context shows an attached role and permissions

**Minimum for formal path**: Hops 1, 2, and 4 must be CONFIRMED.

**Impact**: A web compromise at the load-balanced edge becomes cloud compromise through the target instance role.

**Remediation priority**:
1. Add WAF and tighten application exposure
2. Reduce target-instance IAM permissions
3. Harden target instances and metadata settings

---

### AP-REF-04: Public ALB Rule Exposes Admin Path

**Pattern**: Internet -> Public ALB -> Path / Host Rule -> Admin Target

**Chain hops**:
1. **Entry**: ALB is internet-facing
2. **Rule Exposure**: listener rule forwards public traffic for an admin-looking path or host
3. **Sensitive Target**: the rule points to an admin, internal, or privileged target group

**Evidence requirements**:
- Hop 1 CONFIRMED: scheme visible
- Hop 2 CONFIRMED: rule conditions visible
- Hop 3 CONFIRMED: rule action and target-group naming/port indicate sensitive backend

**Minimum for formal path**: All three hops should be CONFIRMED.

**Impact**: A path or host rule exposes an internal administration surface to the internet through the load balancer.

**Remediation priority**:
1. Remove or restrict the public rule
2. Move admin services behind private access
3. Validate that target groups align with intended audience

---

### AP-REF-05: Public Load Balancer + No Access Logs = Undetected Exposure

**Pattern**: Internet-Facing LB -> Sensitive Exposure -> No Access Logs

**Chain hops**:
1. **Public Exposure**: load balancer is internet-facing
2. **Sensitive Listener or Backend**: listener or rule exposes an important service
3. **Visibility Gap**: access logs are disabled

**Evidence requirements**:
- Hop 1 CONFIRMED: scheme visible
- Hop 2 CONFIRMED: sensitive listener/rule/target path visible
- Hop 3 CONFIRMED: logging disabled in attributes

**Minimum for formal path**: All three hops should be CONFIRMED.

**Impact**: Abuse of an already exposed service is harder to investigate or detect at the edge.

**Remediation priority**:
1. Break the exposure path first
2. Enable access logs immediately
3. Ensure retention and monitoring exist downstream

---

### AP-REF-06: Public ALB Without WAF Protects High-Risk Web Surface

**Pattern**: Internet -> Public ALB -> No WAF -> App Target

**Chain hops**:
1. **Entry**: internet-facing ALB serves HTTP or HTTPS
2. **No WAF**: no web ACL is attached
3. **App Target**: ALB forwards to EC2 or IP targets hosting the application

**Evidence requirements**:
- Hop 1 CONFIRMED: public ALB and web listener visible
- Hop 2 CONFIRMED: WAF dependency context shows no association
- Hop 3 CONFIRMED: target group has application targets

**Minimum for formal path**: All three hops should be CONFIRMED.

**Impact**: The application-facing edge lacks a common application-layer filtering control, increasing the exposure of the backend app surface.

**Remediation priority**:
1. Attach an approved WAF ACL
2. Tighten public listeners and rules
3. Review backend hardening and rate limiting

---

### AP-REF-07: Public NLB to Private Target Bypasses Intended Isolation

**Pattern**: Internet -> Public NLB -> Private Subnet Target -> Internal Service Becomes Public

**Chain hops**:
1. **Entry**: NLB is internet-facing
2. **Private Backend**: targets sit in private subnets or appear intended to be internal
3. **Forwarding Path**: listener exposes those targets publicly

**Evidence requirements**:
- Hop 1 CONFIRMED: scheme visible
- Hop 2 CONFIRMED: subnet or instance context shows private placement
- Hop 3 CONFIRMED: listener and target-group mapping visible

**Minimum for formal path**: All three hops should be CONFIRMED.

**Impact**: The NLB turns a privately placed service into an externally reachable endpoint, bypassing the intuition that private subnet placement alone protects it.

**Remediation priority**:
1. Move the service behind an internal LB
2. Restrict listener exposure
3. Re-check SGs and route intent around the backend

---

### AP-REF-08: Public ALB to EC2 Target to S3 / Secrets Through Instance Role

**Pattern**: Internet -> Public ALB -> EC2 Target -> IAM Role -> Sensitive AWS Service

**Chain hops**:
1. **Entry**: public ALB fronts a web listener
2. **Application Target**: target group includes EC2 instances
3. **Target Compromise**: attacker gains code execution on the target app
4. **Role Permissions**: target role has S3, Secrets Manager, or IAM write access

**Evidence requirements**:
- Hop 1 CONFIRMED: public listener visible
- Hop 2 CONFIRMED: target group contains EC2 instances
- Hop 3 INFERRED: application compromise is the attacker assumption
- Hop 4 CONFIRMED: IAM dependency context shows sensitive permissions

**Minimum for formal path**: Hops 1, 2, and 4 must be CONFIRMED.

**Impact**: The load balancer is the front door for a path that ends in cloud-level data access or privilege escalation through the backend role.

**Remediation priority**:
1. Reduce public app exposure and add WAF
2. Remove sensitive permissions from target roles
3. Harden target instances and metadata settings

---

## 5. False Positive and Context Controls

Do **NOT** overstate the following:

- **Public ALB on ports 80/443 for a legitimate website** -> expected by itself
- **Internal LBs with broad private-source access** -> often architectural, not automatically a finding
- **No WAF on non-HTTP LBs** -> not applicable
- **NLB TLS pass-through** -> do not assume weak TLS if the backend legitimately terminates encryption
- **HTTP listener that only performs redirect to HTTPS** -> lower severity or no finding when the redirect is proven

Always ask:
- Is the LB actually internet-facing?
- Does the listener expose a truly sensitive service, or a normal public web edge?
- Does the target mapping turn a private service into a public one?

---

## 6. Severity Tuning Rules

### Raise severity when:
- Listener is public and exposes admin or data-service ports
- Target groups contain production, admin, auth, or customer-data systems
- WAF and logging are both absent on a public high-risk application edge
- Public LB fronts EC2 targets with powerful IAM roles
- The same LB or listener exposes multiple sensitive targets

### Lower severity when:
- LB is clearly internal
- Public web serving is expected and HTTPS enforcement is strong
- Missing WAF or logging is the only issue on a low-risk web edge
- Finding is mostly hygiene with no real exposed path

---

## 7. Dependency Context Usage Rules (ELB Specific)

### You MAY:
- Use EC2 data to understand SGs, subnet intent, target instances, and public/private backend placement
- Use WAF data to validate whether public ALBs have web ACL coverage
- Use ACM data to describe certificate and listener context where present
- Use IAM data to validate backend-role blast radius for EC2 targets
- Reference dependency data in `attack_paths[].chain[]` and remediation

### You MUST NOT:
- Perform a standalone EC2, IAM, WAF, or ACM audit from dependency context
- Invent application vulnerabilities or backend behavior not supported by the scan
- Treat dependency context as a full scan of the target service

### When dependency context is missing:
- Keep the ELB-direct finding
- Note that backend reachability, WAF, or IAM blast radius could not be fully validated
- Do NOT create formal attack paths with more than 1 unexplained inference

---

## 8. Attack Path Construction Workflow

Follow this order when analyzing ELB scan output:

### Step 1: Build relationship maps (Section 2)
Map load balancers, listeners, rules, target groups, target instances, and edge-control attributes.

### Step 2: Identify direct findings (Section 3)
Emit listener, TLS, logging, WAF, SG, and sensitive-target findings.

### Step 3: Attempt attack path matching (Section 4)
Prioritize internet-facing listeners first, then map them to backend targets and cloud blast radius.

### Step 4: Cross-reference findings and paths
- Attach `attack_path_ids` where formal paths exist
- Use real LB names/ARNs, listeners, target groups, and target identifiers

### Step 5: Rank remediation
- Break public exposure to sensitive services first
- Then improve WAF, TLS, and logging
- Then reduce backend IAM blast radius

### Step 6: Write narrative and quick wins
- Narrative should lead with the most dangerous exposed listener path
- Quick wins should prioritize listener removal, SG tightening, and WAF/logging on public edges

---

## 9. Remediation Playbooks

### Playbook: Remove Public Exposure to Sensitive Services
1. Inventory internet-facing listeners and ports
2. Remove listeners that expose admin or data ports
3. Move sensitive services behind internal load balancers
4. Restrict target access to approved upstream tiers only

### Playbook: Harden the Public Web Edge
1. Ensure HTTP redirects to HTTPS where appropriate
2. Upgrade listener TLS policies
3. Validate certificate coverage and rotation
4. Attach WAF to public ALBs

### Playbook: Improve Edge Visibility
1. Enable access logs for public and important load balancers
2. Confirm log destination ownership and retention
3. Monitor for unexpected listener or rule changes

### Playbook: Reduce Backend Cloud Blast Radius
1. Identify public LBs that front EC2 targets with IAM roles
2. Reduce target-role permissions to least privilege
3. Harden target instances and metadata settings
4. Separate internet-facing and internal workload roles

---

## 10. Output Guidance

### Finding output
- Refer to actual **LB names/ARNs, listener ARNs, target groups, ports, SG IDs, and target instance IDs**
- State whether the LB is internet-facing, what listener or rule creates the risk, and what backend it exposes
- Distinguish between **expected public web delivery** and **unexpected exposure of sensitive services**
- Use concise impact language focused on what the public edge reaches

### Attack path output
- `full_path_summary` should look like `Internet -> alb-app-prod -> listener-443 -> tg-admin -> i-0123`
- Each `INFERRED` hop must explain what additional evidence would confirm it
- `remediation_priority` should start with removing or restricting the public listener path

---

## 11. Minimum ELB Coverage Checklist

A thorough ELB analysis must evaluate:

### Direct ELB findings:
- [ ] Internet-facing listeners on admin or data-service ports
- [ ] Public HTTP-only listeners without strong HTTPS enforcement
- [ ] Weak TLS policies on public listeners
- [ ] Public ALBs without WAF
- [ ] Access logging on public or important load balancers
- [ ] Deletion protection on important ALB/NLB resources
- [ ] Broad ALB/CLB SG exposure on non-web ports
- [ ] Public listeners forwarding to sensitive backend targets
- [ ] HTTP hardening attributes where available

### Attack path evaluation (using dependency context):
- [ ] Public LB to sensitive backend port (AP-REF-01)
- [ ] Public LB to database service (AP-REF-02)
- [ ] Public ALB to EC2 target to IAM role pivot (AP-REF-03)
- [ ] Public ALB admin-path exposure (AP-REF-04)
- [ ] Public exposure + no access logs (AP-REF-05)
- [ ] Public ALB without WAF on app surface (AP-REF-06)
- [ ] Public NLB to private target isolation bypass (AP-REF-07)
- [ ] Public ALB to EC2 target to sensitive AWS service via role (AP-REF-08)

If these are not evaluated, the ELB analysis is incomplete.
