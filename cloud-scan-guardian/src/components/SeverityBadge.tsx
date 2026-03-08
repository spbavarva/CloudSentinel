import { Severity, OverallHealth } from '@/lib/types';

const severityStyles: Record<Severity, string> = {
  CRITICAL: 'bg-severity-critical/10 text-severity-critical',
  HIGH: 'bg-severity-high/10 text-severity-high',
  MEDIUM: 'bg-severity-medium/10 text-severity-medium',
  LOW: 'bg-severity-low/10 text-severity-low',
  NEEDS_REVIEW: 'bg-severity-needs-review/10 text-severity-needs-review',
};

// Custom opacity classes since we defined them in index.css
const severityBgStyles: Record<string, string> = {
  'bg-severity-needs-review/10': 'bg-[hsl(270_60%_65%/0.1)]',
};

export function SeverityBadge({ severity, count }: { severity: Severity; count?: number }) {
  return (
    <span className={`inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-semibold ${severityStyles[severity]}`}>
      {severity}
      {count !== undefined && <span className="ml-0.5 opacity-80">{count}</span>}
    </span>
  );
}

const healthStyles: Record<OverallHealth, string> = {
  SECURE: 'bg-health-secure/15 text-health-secure',
  MOSTLY_SECURE: 'bg-[hsl(199_89%_48%/0.15)] text-[hsl(199_89%_48%)]',
  AT_RISK: 'bg-[hsl(25_95%_53%/0.15)] text-[hsl(25_95%_53%)]',
  CRITICAL_RISK: 'bg-[hsl(0_72%_51%/0.15)] text-[hsl(0_72%_51%)]',
  SCAN_INCOMPLETE: 'bg-[hsl(215_15%_55%/0.15)] text-[hsl(215_15%_55%)]',
};

export function HealthBadge({ health }: { health: OverallHealth }) {
  return (
    <span className={`inline-flex items-center rounded-lg px-3 py-1 text-sm font-bold ${healthStyles[health]}`}>
      {health.replace('_', ' ')}
    </span>
  );
}
