import { useEffect, useMemo, useRef, useState } from 'react';
import { Activity, Bot, Cpu, TerminalSquare } from 'lucide-react';
import { ProgressKind, ProgressPhase, ServiceType } from '@/lib/types';
import { ScrollArea } from '@/components/ui/scroll-area';

interface ActivityItem {
  id: string;
  service: ServiceType;
  message: string;
  phase?: ProgressPhase;
  progressKind?: ProgressKind;
  detail?: string;
  commandLabel?: string;
  awsService?: string;
  commandName?: string;
  startedAt?: string;
  provider?: 'auto' | 'codex' | 'claude';
  aiStage?: string;
  elapsedSeconds?: number;
}

interface ScanActivityProps {
  items: ActivityItem[];
  isScanning: boolean;
}

const phaseLabels: Record<ProgressPhase, string> = {
  scan: 'Collecting Evidence',
  parse: 'Parsing',
  prompt: 'Prompt Build',
  analysis: 'AI Analysis',
  validate: 'Validation',
};

const serviceLabels: Record<ServiceType, string> = {
  ec2: 'EC2',
  s3: 'S3',
  iam: 'IAM',
  vpc: 'VPC',
  rds: 'RDS',
  ebs: 'EBS',
  ami: 'AMI',
  elb: 'ELB',
};

function formatTime(value?: string) {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function currentLabel(item: ActivityItem | undefined) {
  if (!item) return 'Preparing scan...';
  if (item.progressKind === 'command' && item.commandLabel) return item.commandLabel;
  return item.detail || item.message;
}

function formatDuration(totalSeconds: number) {
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  if (minutes <= 0) return `${seconds}s`;
  return `${minutes}m ${String(seconds).padStart(2, '0')}s`;
}

function titleCase(value?: string) {
  if (!value) return null;
  return value
    .split('_')
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}

function AIHeartbeatCard({
  provider,
  detail,
  elapsedSeconds,
}: {
  provider: string;
  detail: string;
  elapsedSeconds: number;
}) {
  return (
    <div className="ai-heartbeat-card mb-5 overflow-hidden rounded-2xl border border-primary/15 px-4 py-4">
      <div className="mb-3 flex items-center justify-between gap-3">
        <div className="flex min-w-0 items-center gap-2.5">
          <div className="ai-heartbeat-dot" />
          <div className="min-w-0">
            <div className="truncate text-sm font-semibold text-foreground">
              {provider} is analyzing findings
            </div>
            <div className="truncate text-[11px] text-foreground/55">{detail}</div>
          </div>
        </div>
        <div className="text-right">
          <div className="text-[10px] uppercase tracking-[0.14em] text-foreground/35">Live heartbeat</div>
          <div className="mt-0.5 text-xs font-medium text-foreground/70">{formatDuration(elapsedSeconds)}</div>
        </div>
      </div>

      <div className="relative overflow-hidden rounded-xl border border-white/5 bg-black/20 px-2 py-3">
        <svg
          viewBox="0 0 320 64"
          preserveAspectRatio="none"
          className="h-16 w-full"
          aria-hidden="true"
        >
          <path
            d="M0 34 L24 34 L36 26 L44 44 L54 16 L68 56 L84 22 L96 40 L110 34 L144 34 L156 26 L166 42 L178 14 L194 56 L208 22 L220 40 L234 34 L268 34 L280 26 L290 42 L302 14 L316 56 L320 38"
            className="ai-heartbeat-wave ai-heartbeat-wave-base"
            pathLength={100}
          />
          <path
            d="M0 34 L24 34 L36 26 L44 44 L54 16 L68 56 L84 22 L96 40 L110 34 L144 34 L156 26 L166 42 L178 14 L194 56 L208 22 L220 40 L234 34 L268 34 L280 26 L290 42 L302 14 L316 56 L320 38"
            className="ai-heartbeat-wave ai-heartbeat-wave-glow"
            pathLength={100}
          />
          <path
            d="M0 34 L24 34 L36 26 L44 44 L54 16 L68 56 L84 22 L96 40 L110 34 L144 34 L156 26 L166 42 L178 14 L194 56 L208 22 L220 40 L234 34 L268 34 L280 26 L290 42 L302 14 L316 56 L320 38"
            className="ai-heartbeat-wave ai-heartbeat-wave-trace"
            pathLength={100}
          />
        </svg>
      </div>
    </div>
  );
}

export default function ScanActivity({ items, isScanning }: ScanActivityProps) {
  const scrollRootRef = useRef<HTMLDivElement | null>(null);
  const [stickToBottom, setStickToBottom] = useState(true);
  const [heartbeatElapsed, setHeartbeatElapsed] = useState(0);
  const latest = items[items.length - 1];
  const timeline = useMemo(() => items, [items]);
  const latestPhase = latest?.phase ? phaseLabels[latest.phase] : 'Preparing';
  const latestTime = formatTime(latest?.startedAt);
  const activeAiItem = useMemo(() => {
    if (!isScanning || latest?.phase !== 'analysis') return null;
    return [...items].reverse().find((item) => item.phase === 'analysis') ?? null;
  }, [isScanning, items, latest?.phase]);

  useEffect(() => {
    const viewport = scrollRootRef.current?.querySelector('[data-radix-scroll-area-viewport]') as HTMLDivElement | null;
    if (!viewport) return;

    const handleScroll = () => {
      const distanceFromBottom = viewport.scrollHeight - viewport.scrollTop - viewport.clientHeight;
      setStickToBottom(distanceFromBottom < 48);
    };

    handleScroll();
    viewport.addEventListener('scroll', handleScroll);
    return () => viewport.removeEventListener('scroll', handleScroll);
  }, []);

  useEffect(() => {
    if (!stickToBottom) return;
    const viewport = scrollRootRef.current?.querySelector('[data-radix-scroll-area-viewport]') as HTMLDivElement | null;
    if (!viewport) return;
    viewport.scrollTop = viewport.scrollHeight;
  }, [timeline, stickToBottom]);

  useEffect(() => {
    if (!activeAiItem) {
      setHeartbeatElapsed(0);
      return;
    }

    const baseElapsed = activeAiItem.elapsedSeconds ?? 0;
    const baseStartedAt = activeAiItem.startedAt ? new Date(activeAiItem.startedAt).getTime() : Date.now();

    const syncElapsed = () => {
      const additionalSeconds = Math.max(0, Math.floor((Date.now() - baseStartedAt) / 1000));
      setHeartbeatElapsed(baseElapsed + additionalSeconds);
    };

    syncElapsed();
    const timer = window.setInterval(syncElapsed, 1000);
    return () => window.clearInterval(timer);
  }, [activeAiItem]);

  return (
    <div className="glass rounded-2xl p-6">
      <div className="mb-4 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <Activity size={15} className="text-primary" />
          <h3 className="text-[11px] font-semibold text-foreground/60 uppercase tracking-[0.15em]">
            Live Activity
          </h3>
        </div>
        <div className="text-right">
          <div className="text-[10px] text-foreground/45">
            {isScanning ? 'Updating live' : 'Last activity'}
          </div>
          {latestTime && (
            <div className="mt-0.5 text-[10px] text-foreground/30">{latestTime}</div>
          )}
        </div>
      </div>

      <div className="mb-5 grid gap-3 md:grid-cols-3">
        <div className="rounded-xl bg-muted/20 p-3">
          <div className="mb-1 text-[10px] uppercase tracking-[0.15em] text-foreground/45">Current Phase</div>
          <div className="text-sm font-semibold text-foreground">{latestPhase}</div>
        </div>
        <div className="rounded-xl bg-muted/20 p-3">
          <div className="mb-1 text-[10px] uppercase tracking-[0.15em] text-foreground/45">Service</div>
          <div className="text-sm font-semibold text-foreground">
            {latest ? serviceLabels[latest.service] : 'Starting'}
          </div>
        </div>
        <div className="rounded-xl bg-muted/20 p-3">
          <div className="mb-1 text-[10px] uppercase tracking-[0.15em] text-foreground/45">Now Running</div>
          <div className="truncate text-sm font-semibold text-foreground">{currentLabel(latest)}</div>
        </div>
      </div>

      {timeline.length === 0 ? (
        <div className="rounded-xl bg-muted/15 px-4 py-5 text-sm text-foreground/55">
          Preparing the scan pipeline and waiting for the first progress update...
        </div>
      ) : (
        <>
          {activeAiItem && (
            <AIHeartbeatCard
              provider={(activeAiItem.provider ?? 'ai').toUpperCase()}
              detail={activeAiItem.detail || 'Running analysis on the prepared evidence bundle'}
              elapsedSeconds={heartbeatElapsed}
            />
          )}

          <ScrollArea ref={scrollRootRef} className="h-[480px] pr-3">
            <div className="space-y-2">
              {timeline.map((item) => {
                const timeLabel = formatTime(item.startedAt);
                const isCommand = item.progressKind === 'command';
                const isAi = item.progressKind === 'ai';
                const providerLabel = item.provider ? item.provider.toUpperCase() : null;
                const aiStageLabel = titleCase(item.aiStage);
                return (
                  <div key={item.id} className="rounded-xl bg-muted/15 px-4 py-3">
                    <div className="mb-1 flex items-start justify-between gap-3">
                      <div className="flex min-w-0 items-center gap-2">
                        {isCommand ? (
                          <TerminalSquare size={14} className="mt-0.5 flex-shrink-0 text-primary" />
                        ) : isAi ? (
                          <Bot size={14} className="mt-0.5 flex-shrink-0 text-primary" />
                        ) : (
                          <Cpu size={14} className="mt-0.5 flex-shrink-0 text-primary" />
                        )}
                        <div className="min-w-0">
                          <div className="truncate text-sm font-medium text-foreground">{item.message}</div>
                          {item.detail && item.detail !== item.message && (
                            <div className="mt-0.5 text-[11px] text-foreground/50">{item.detail}</div>
                          )}
                        </div>
                      </div>
                      {timeLabel && (
                        <span className="whitespace-nowrap text-[10px] text-foreground/35">{timeLabel}</span>
                      )}
                    </div>
                    <div className="flex flex-wrap items-center gap-2 text-[10px] uppercase tracking-[0.12em] text-foreground/35">
                      <span>{serviceLabels[item.service]}</span>
                      {item.phase && <span>{phaseLabels[item.phase]}</span>}
                      {providerLabel && <span>{providerLabel}</span>}
                      {aiStageLabel && <span>{aiStageLabel}</span>}
                      {typeof item.elapsedSeconds === 'number' && item.elapsedSeconds > 0 && (
                        <span>{item.elapsedSeconds}s elapsed</span>
                      )}
                      {item.commandLabel && <span className="normal-case tracking-normal">{item.commandLabel}</span>}
                      {!item.commandLabel && item.awsService && <span>{item.awsService}</span>}
                      {item.commandName && <span>{item.commandName}</span>}
                    </div>
                  </div>
                );
              })}
            </div>
          </ScrollArea>
        </>
      )}
    </div>
  );
}
