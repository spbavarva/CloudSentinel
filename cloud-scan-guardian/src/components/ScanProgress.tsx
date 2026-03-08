import { Server, Database, User, Network, Loader2, CheckCircle2, XCircle } from 'lucide-react';
import { ServiceType } from '@/lib/types';

const serviceIcons: Record<ServiceType, React.ReactNode> = {
  ec2: <Server size={18} />,
  s3: <Database size={18} />,
  iam: <User size={18} />,
  vpc: <Network size={18} />,
};

const serviceLabels: Record<ServiceType, string> = {
  ec2: 'EC2',
  s3: 'S3',
  iam: 'IAM',
  vpc: 'VPC',
};

export type ServiceStatus = 'pending' | 'scanning' | 'done' | 'error';

interface ProgressRow {
  service: ServiceType;
  status: ServiceStatus;
  message: string;
}

interface ScanProgressProps {
  rows: ProgressRow[];
  onCancel: () => void;
}

export default function ScanProgress({ rows, onCancel }: ScanProgressProps) {
  return (
    <div className="rounded-2xl border border-border bg-card p-6">
      <h2 className="mb-4 text-lg font-semibold text-foreground">Scan Progress</h2>
      <div className="space-y-3">
        {rows.map(row => (
          <div
            key={row.service}
            className="flex items-center gap-3 rounded-xl border border-border bg-muted/50 px-4 py-3"
          >
            <span className="text-muted-foreground">{serviceIcons[row.service]}</span>
            <span className="w-10 text-sm font-semibold text-foreground">{serviceLabels[row.service]}</span>
            <div className="flex-1 truncate text-xs text-muted-foreground">
              {row.message || (row.status === 'pending' ? 'Waiting...' : '')}
            </div>
            <div>
              {row.status === 'scanning' && <Loader2 size={18} className="animate-spin text-primary" />}
              {row.status === 'done' && <CheckCircle2 size={18} className="text-health-secure" />}
              {row.status === 'error' && <XCircle size={18} className="text-severity-critical" />}
              {row.status === 'pending' && <div className="h-2 w-2 rounded-full bg-muted-foreground/30" />}
            </div>
          </div>
        ))}
      </div>
      <button
        onClick={onCancel}
        className="mt-4 text-xs text-muted-foreground hover:text-foreground transition-colors"
      >
        ← Back to Configuration
      </button>
    </div>
  );
}
