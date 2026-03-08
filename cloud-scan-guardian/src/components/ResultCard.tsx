import { useState } from 'react';
import { ChevronDown, ChevronRight, ExternalLink, Link2 } from 'lucide-react';
import { ServiceAnalysis, Finding, AttackPath, Severity } from '@/lib/types';
import { SeverityBadge, HealthBadge } from './SeverityBadge';
import CopyButton from './CopyButton';
import { format } from 'date-fns';

const severityOrder: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NEEDS_REVIEW'];

function Collapsible({ label, children, defaultOpen = false }: { label: string; children: React.ReactNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div>
      <button onClick={() => setOpen(!open)} className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors">
        {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        {label}
      </button>
      {open && <div className="mt-1.5 pl-4">{children}</div>}
    </div>
  );
}

function FindingCard({ finding }: { finding: Finding }) {
  return (
    <div className="rounded-xl border border-border bg-muted/30 p-4 space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={finding.severity} />
        <code className="text-xs font-mono text-muted-foreground">{finding.id}</code>
        <span className="rounded-md bg-secondary px-2 py-0.5 text-xs text-secondary-foreground">{finding.resource_type}</span>
        <span className="rounded-md bg-secondary px-2 py-0.5 text-xs text-secondary-foreground">{finding.category}</span>
        {finding.attack_path_ids?.length > 0 && (
          <span className="rounded-md bg-primary/10 px-2 py-0.5 text-xs text-primary flex items-center gap-1">
            <Link2 size={10} /> Attack path
          </span>
        )}
      </div>
      <div>
        <p className="text-sm font-semibold text-foreground">{finding.issue_title}</p>
        <p className="mt-1 text-xs text-muted-foreground">{finding.issue_description}</p>
      </div>
      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground font-mono">
        <span>{finding.resource_name}</span>
        <span className="opacity-50">·</span>
        <span>{finding.resource_id}</span>
      </div>
      <div className="space-y-1">
        <Collapsible label="Impact">
          <p className="text-xs text-muted-foreground">{finding.impact}</p>
        </Collapsible>
        <Collapsible label="Fix Command">
          <div className="relative rounded-lg bg-background p-3 font-mono text-xs text-foreground overflow-x-auto">
            <div className="absolute right-2 top-2"><CopyButton text={finding.fix_command} /></div>
            <pre className="whitespace-pre-wrap pr-16">{finding.fix_command}</pre>
          </div>
        </Collapsible>
        <Collapsible label="Fix Explanation">
          <p className="text-xs text-muted-foreground">{finding.fix_explanation}</p>
        </Collapsible>
      </div>
      {finding.aws_doc_reference && (
        <a href={finding.aws_doc_reference} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-xs text-primary hover:underline">
          <ExternalLink size={10} /> AWS Docs
        </a>
      )}
    </div>
  );
}

function AttackPathCard({ path }: { path: AttackPath }) {
  return (
    <div className="rounded-xl border border-border bg-muted/30 p-4 space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={path.severity} />
        <code className="text-xs font-mono text-muted-foreground">{path.id}</code>
        <span className="text-sm font-semibold text-foreground">{path.title}</span>
      </div>

      {/* Chain visualization */}
      <div className="space-y-0">
        {path.chain.map((step, i) => (
          <div key={i} className="flex items-start gap-3">
            <div className="flex flex-col items-center">
              <div className="flex h-7 w-7 items-center justify-center rounded-full border border-border bg-secondary text-xs font-bold text-foreground">
                {step.step}
              </div>
              {i < path.chain.length - 1 && <div className="h-6 w-px bg-border" />}
            </div>
            <div className="pb-3">
              <p className="text-xs font-semibold text-foreground">{step.resource_name}</p>
              <p className="text-xs text-muted-foreground">{step.action}</p>
              <div className="mt-1 flex items-center gap-2">
                <span className={`rounded-md px-1.5 py-0.5 text-[10px] font-medium ${
                  step.evidence_status === 'CONFIRMED'
                    ? 'bg-health-secure/15 text-health-secure'
                    : 'bg-severity-medium/10 text-severity-medium'
                }`}>
                  {step.evidence_status}
                </span>
                <span className="text-[10px] text-muted-foreground/70">{step.evidence}</span>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Full path summary */}
      <div className="rounded-lg bg-background px-3 py-2 font-mono text-xs text-muted-foreground">
        {path.full_path_summary}
      </div>

      <Collapsible label="Impact" defaultOpen>
        <p className="text-xs text-muted-foreground">{path.impact}</p>
      </Collapsible>

      {path.remediation_priority?.length > 0 && (
        <Collapsible label="Remediation Priority" defaultOpen>
          <ol className="list-decimal pl-4 space-y-1 text-xs text-muted-foreground">
            {path.remediation_priority.map((r, i) => (
              <li key={i}>
                <code className="text-primary">{r.finding_id}</code> — {r.action}
              </li>
            ))}
          </ol>
        </Collapsible>
      )}
    </div>
  );
}

const tabs = ['Summary', 'Narrative', 'Quick Wins', 'Findings', 'Attack Paths'] as const;

export default function ResultCard({ analysis }: { analysis: ServiceAnalysis }) {
  const [activeTab, setActiveTab] = useState<typeof tabs[number]>('Summary');
  const summary = analysis.account_summary;
  const sortedFindings = [...analysis.findings].sort(
    (a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)
  );

  return (
    <div className="rounded-2xl border border-border bg-card overflow-hidden">
      {/* Tab bar */}
      <div className="flex overflow-x-auto border-b border-border bg-muted/30">
        {tabs.map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`whitespace-nowrap px-4 py-3 text-xs font-medium transition-colors ${
              activeTab === tab
                ? 'border-b-2 border-primary text-primary'
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            {tab}
            {tab === 'Findings' && <span className="ml-1.5 opacity-60">({analysis.findings.length})</span>}
            {tab === 'Attack Paths' && <span className="ml-1.5 opacity-60">({analysis.attack_paths.length})</span>}
          </button>
        ))}
      </div>

      <div className="p-5">
        {activeTab === 'Summary' && (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-3">
              <span className="text-lg font-bold text-foreground uppercase">{analysis.service}</span>
              <HealthBadge health={summary.overall_health} />
              <span className="text-xs text-muted-foreground">
                {format(new Date(analysis.scan_timestamp), 'PPpp')}
              </span>
            </div>
            <div className="flex flex-wrap gap-2">
              {severityOrder.map(sev => (
                <SeverityBadge key={sev} severity={sev} count={summary.severity_breakdown[sev] || 0} />
              ))}
            </div>
            <div className="grid grid-cols-3 gap-3 text-center">
              <div className="rounded-xl bg-muted p-3">
                <p className="text-2xl font-bold text-foreground">{summary.total_resources_scanned}</p>
                <p className="text-xs text-muted-foreground">Resources</p>
              </div>
              <div className="rounded-xl bg-muted p-3">
                <p className="text-2xl font-bold text-foreground">{summary.total_findings}</p>
                <p className="text-xs text-muted-foreground">Findings</p>
              </div>
              <div className="rounded-xl bg-muted p-3">
                <p className="text-2xl font-bold text-foreground">{summary.total_attack_paths}</p>
                <p className="text-xs text-muted-foreground">Attack Paths</p>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'Narrative' && (
          <div className="prose prose-invert max-w-none text-sm text-muted-foreground leading-relaxed whitespace-pre-wrap">
            {analysis.narrative || 'No narrative available.'}
          </div>
        )}

        {activeTab === 'Quick Wins' && (
          <div className="space-y-2">
            {analysis.quick_wins?.length ? analysis.quick_wins.map((qw, i) => (
              <div key={i} className="rounded-xl border border-[hsl(var(--health-secure)/0.2)] bg-health-secure/15 p-4 space-y-1">
                <div className="flex items-center gap-2">
                  <code className="rounded bg-background px-1.5 py-0.5 text-xs font-mono text-primary">{qw.finding_id}</code>
                  <span className="rounded-md bg-background px-2 py-0.5 text-[10px] font-medium text-muted-foreground">{qw.effort}</span>
                </div>
                <p className="text-sm font-medium text-foreground">{qw.action}</p>
                <p className="text-xs text-muted-foreground">{qw.impact}</p>
              </div>
            )) : (
              <p className="text-sm text-muted-foreground">No quick wins identified.</p>
            )}
          </div>
        )}

        {activeTab === 'Findings' && (
          <div className="space-y-3">
            {sortedFindings.length ? sortedFindings.map(f => (
              <FindingCard key={f.id} finding={f} />
            )) : (
              <p className="text-sm text-muted-foreground">No findings.</p>
            )}
          </div>
        )}

        {activeTab === 'Attack Paths' && (
          <div className="space-y-3">
            {analysis.attack_paths?.length ? analysis.attack_paths.map(ap => (
              <AttackPathCard key={ap.id} path={ap} />
            )) : (
              <p className="text-sm text-muted-foreground">No attack paths identified.</p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
