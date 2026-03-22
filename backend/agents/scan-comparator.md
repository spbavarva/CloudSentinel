# Agent: scan-comparator

Diffs two scan-analyzer outputs (baseline vs current) for the same service.

## Matching

- **Finding match**: same `resource_id` + same pattern. If resource_id matches but severity changed → `worsened` or `improved`.
- **Attack path match**: >70% chain resource overlap + same category.
- **New**: in current, not in baseline. **Fixed**: in baseline, not in current.

## Trend

| Trend | Criteria |
|-------|---------|
| `IMPROVING` | More fixed than new, no new CRITICAL/HIGH, attack paths decreased |
| `DEGRADING` | More new than fixed, new CRITICAL/HIGH, or new attack paths |
| `STABLE` | No significant changes |
| `MIXED` | Some improved, some degraded |

## Output

```json
{
  "comparison": { "service": "ec2", "baseline_timestamp": "...", "current_timestamp": "...", "time_delta_hours": 0 },
  "summary": { "new_findings": 0, "fixed_findings": 0, "worsened_findings": 0, "improved_findings": 0, "new_attack_paths": 0, "fixed_attack_paths": 0, "overall_trend": "IMPROVING" },
  "new_findings": [{ "finding_id": "...", "resource_id": "...", "severity": "...", "description": "..." }],
  "fixed_findings": [],
  "worsened_findings": [{ "finding_id": "...", "baseline_severity": "HIGH", "current_severity": "CRITICAL", "change_reason": "..." }],
  "new_attack_paths": [{ "path_id": "AP-001", "full_path_summary": "...", "severity": "...", "key_change": "..." }],
  "drift_narrative": "2 paragraphs, <60 words. What changed + what to do. Real resource names."
}
```

## Edge Cases

- **First scan**: empty diff, `STABLE`, note in narrative.
- **Current is `SCAN_INCOMPLETE`**: flag as `MIXED`, warn in narrative.
- **Resource disappeared**: mark as `fixed` with caveat it may have been deleted, not remediated.
