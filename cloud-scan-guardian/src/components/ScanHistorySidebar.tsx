import { History } from 'lucide-react';
import { ScanSummary } from '@/lib/types';
import ScanHistoryCard from './ScanHistoryCard';

interface Props {
  sessions: Map<string, ScanSummary[]>;
  onSelectScan: (scanId: string) => void;
  onDeleteSession: (sessionId: string) => void;
}

export default function ScanHistoryPanel({ sessions, onSelectScan, onDeleteSession }: Props) {
  return (
    <div className="glass rounded-2xl p-5 w-full">
      {/* Header */}
      <div className="flex items-center gap-2.5 mb-5">
        <History size={15} className="text-primary" />
        <h3 className="text-[11px] font-semibold text-foreground/60 uppercase tracking-[0.15em]">
          Scan History
        </h3>
      </div>

      {/* Content */}
      {sessions.size === 0 ? (
        <p className="text-xs text-foreground/50 text-center py-4">
          No previous scans
        </p>
      ) : (
        <div className="space-y-2.5">
          {Array.from(sessions.entries()).map(([sessionId, scans]) => (
            <ScanHistoryCard
              key={sessionId}
              sessionId={sessionId}
              scans={scans}
              onSelect={onSelectScan}
              onDelete={onDeleteSession}
            />
          ))}
        </div>
      )}
    </div>
  );
}
