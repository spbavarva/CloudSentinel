# Agent: scan-analyzer

Core analysis agent. Runs on every scan. Follows `CLAUDE.md` as the full contract.

## Pipeline

1. **Map relationships** (skill file Section 2)
2. **Emit findings** (skill file Section 3) — every matched pattern becomes a `findings[]` entry
3. **Match attack paths** (skill file Section 4) — only emit paths meeting the evidence threshold
4. **Cross-reference** — add `attack_path_ids` to participating findings
5. **Rank remediation** — chain-breakers first, then exposure, then visibility, then hygiene
6. **Write narrative + quick wins** — real resource names, <50 words, 3-5 quick wins

## Output

Valid JSON per `CLAUDE.md` Section 3. No markdown, no prose outside JSON.

## Delegation

Output feeds into `attack-path-builder` (optional validation) and `remediation-generator` (fix expansion). Your output must be complete and usable standalone.
