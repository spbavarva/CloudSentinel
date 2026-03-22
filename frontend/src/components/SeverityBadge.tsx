import { Severity, OverallHealth } from '@/lib/types';

const severityStyles: Record<Severity, string> = {
  CRITICAL: 'bg-severity-critical/10 text-severity-critical border border-[hsl(var(--severity-critical)/0.2)]',
  HIGH: 'bg-severity-high/10 text-severity-high border border-[hsl(var(--severity-high)/0.2)]',
  MEDIUM: 'bg-severity-medium/10 text-severity-medium border border-[hsl(var(--severity-medium)/0.2)]',
  LOW: 'bg-severity-low/10 text-severity-low border border-[hsl(var(--severity-low)/0.15)]',
  NEEDS_REVIEW: 'bg-[hsl(270_70%_65%/0.1)] text-severity-needs-review border border-[hsl(270_70%_65%/0.2)]',
};

export function SeverityBadge({ severity, count }: { severity: Severity; count?: number }) {
  return (
    <span className={`inline-flex items-center gap-1 rounded-lg px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider ${severityStyles[severity]}`}>
      {severity}
      {count !== undefined && <span className="ml-0.5 opacity-70">{count}</span>}
    </span>
  );
}

const healthStyles: Record<OverallHealth, string> = {
  SECURE: 'bg-health-secure/15 text-health-secure border border-[hsl(var(--health-secure)/0.25)]',
  MOSTLY_SECURE: 'bg-[hsl(199_89%_48%/0.12)] text-[hsl(199_89%_48%)] border border-[hsl(199_89%_48%/0.2)]',
  AT_RISK: 'bg-[hsl(25_100%_60%/0.12)] text-[hsl(25_100%_60%)] border border-[hsl(25_100%_60%/0.2)]',
  CRITICAL_RISK: 'bg-[hsl(0_84%_60%/0.12)] text-[hsl(0_84%_60%)] border border-[hsl(0_84%_60%/0.2)]',
  SCAN_INCOMPLETE: 'bg-[hsl(240_5%_55%/0.12)] text-[hsl(240_5%_55%)] border border-[hsl(240_5%_55%/0.15)]',
};

export function HealthBadge({ health }: { health: OverallHealth }) {
  return (
    <span className={`inline-flex items-center rounded-lg px-3 py-1 text-xs font-bold ${healthStyles[health]}`}>
      {health.replace(/_/g, ' ')}
    </span>
  );
}
