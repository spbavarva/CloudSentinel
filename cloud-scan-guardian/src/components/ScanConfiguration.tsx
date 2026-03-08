import { useState } from 'react';
import { Shield, Server, Database, User, Network, Eye, EyeOff, ChevronDown, ChevronUp, Loader2 } from 'lucide-react';
import { motion } from 'framer-motion';
import { ServiceType } from '@/lib/types';

const AWS_REGIONS = [
  'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
  'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1',
  'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-south-1',
];

const SERVICES: { id: ServiceType; label: string; icon: React.ReactNode }[] = [
  { id: 'ec2', label: 'EC2', icon: <Server size={20} /> },
  { id: 's3', label: 'S3', icon: <Database size={20} /> },
  { id: 'iam', label: 'IAM', icon: <User size={20} /> },
  { id: 'vpc', label: 'VPC', icon: <Network size={20} /> },
];

interface ScanConfigProps {
  onStartScan: (config: {
    accessKey: string;
    secretKey: string;
    region: string;
    sessionToken: string | null;
    services: ServiceType[];
  }) => void;
  isScanning: boolean;
  backendOnline: boolean | null;
  initialConfig?: {
    accessKey: string;
    secretKey: string;
    region: string;
  };
}

export default function ScanConfiguration({ onStartScan, isScanning, backendOnline, initialConfig }: ScanConfigProps) {
  const [accessKey, setAccessKey] = useState(initialConfig?.accessKey || '');
  const [secretKey, setSecretKey] = useState(initialConfig?.secretKey || '');
  const [region, setRegion] = useState(initialConfig?.region || 'us-east-1');
  const [sessionToken, setSessionToken] = useState('');
  const [showSecret, setShowSecret] = useState(false);
  const [showSessionToken, setShowSessionToken] = useState(false);
  const [selectedServices, setSelectedServices] = useState<ServiceType[]>(['ec2', 's3', 'iam', 'vpc']);

  const toggleService = (id: ServiceType) => {
    setSelectedServices(prev =>
      prev.includes(id) ? prev.filter(s => s !== id) : [...prev, id]
    );
  };

  const canScan = accessKey.trim() && secretKey.trim() && selectedServices.length > 0 && !isScanning;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!canScan) return;
    onStartScan({
      accessKey,
      secretKey,
      region,
      sessionToken: sessionToken.trim() || null,
      services: selectedServices,
    });
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      className="flex min-h-screen items-center justify-center p-4"
    >
      <div className="w-full max-w-lg">
        {/* Header */}
        <div className="mb-8 text-center">
          <div className="mb-4 flex items-center justify-center gap-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-primary/10 glow-primary">
              <Shield className="text-primary" size={28} />
            </div>
            <h1 className="text-3xl font-bold tracking-tight text-foreground">
              CloudSentinel
            </h1>
          </div>
          <p className="text-sm text-muted-foreground">AI-powered AWS security analysis</p>
          <div className="mt-3 flex items-center justify-center gap-2 text-xs">
            <span className={`h-2 w-2 rounded-full ${backendOnline === true ? 'bg-health-secure' : backendOnline === false ? 'bg-severity-critical' : 'bg-severity-low'}`} />
            <span className="text-muted-foreground">
              {backendOnline === true ? 'Backend connected' : backendOnline === false ? 'Backend offline' : 'Checking...'}
            </span>
          </div>
        </div>

        {/* Form Card */}
        <form onSubmit={handleSubmit} className="rounded-2xl border border-border bg-card p-6 shadow-2xl">
          {/* AWS Credentials */}
          <div className="space-y-4">
            <div>
              <label className="mb-1.5 block text-xs font-medium text-muted-foreground uppercase tracking-wider">
                AWS Access Key ID
              </label>
              <input
                type="text"
                value={accessKey}
                onChange={e => setAccessKey(e.target.value)}
                placeholder="AKIA..."
                className="w-full rounded-lg border border-border bg-muted px-3 py-2.5 font-mono text-sm text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-ring"
              />
            </div>

            <div>
              <label className="mb-1.5 block text-xs font-medium text-muted-foreground uppercase tracking-wider">
                AWS Secret Access Key
              </label>
              <div className="relative">
                <input
                  type={showSecret ? 'text' : 'password'}
                  value={secretKey}
                  onChange={e => setSecretKey(e.target.value)}
                  placeholder="••••••••••••••••"
                  className="w-full rounded-lg border border-border bg-muted px-3 py-2.5 pr-10 font-mono text-sm text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-ring"
                />
                <button
                  type="button"
                  onClick={() => setShowSecret(!showSecret)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  {showSecret ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            <div>
              <label className="mb-1.5 block text-xs font-medium text-muted-foreground uppercase tracking-wider">
                AWS Region
              </label>
              <select
                value={region}
                onChange={e => setRegion(e.target.value)}
                className="w-full rounded-lg border border-border bg-muted px-3 py-2.5 font-mono text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
              >
                {AWS_REGIONS.map(r => (
                  <option key={r} value={r}>{r}</option>
                ))}
              </select>
            </div>

            {/* Session Token (collapsible) */}
            <div>
              <button
                type="button"
                onClick={() => setShowSessionToken(!showSessionToken)}
                className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
              >
                {showSessionToken ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                Optional: Session Token for temporary credentials
              </button>
              {showSessionToken && (
                <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} className="mt-2">
                  <textarea
                    value={sessionToken}
                    onChange={e => setSessionToken(e.target.value)}
                    placeholder="Paste session token here..."
                    rows={3}
                    className="w-full rounded-lg border border-border bg-muted px-3 py-2.5 font-mono text-xs text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-ring resize-none"
                  />
                </motion.div>
              )}
            </div>
          </div>

          {/* Service Selector */}
          <div className="mt-6">
            <label className="mb-3 block text-xs font-medium text-muted-foreground uppercase tracking-wider">
              Services to Scan
            </label>
            <div className="grid grid-cols-4 gap-2">
              {SERVICES.map(svc => {
                const selected = selectedServices.includes(svc.id);
                return (
                  <button
                    key={svc.id}
                    type="button"
                    onClick={() => toggleService(svc.id)}
                    className={`flex flex-col items-center gap-1.5 rounded-xl border-2 px-3 py-3 text-xs font-medium transition-all ${
                      selected
                        ? 'border-primary bg-primary/10 text-primary'
                        : 'border-border bg-muted text-muted-foreground hover:border-primary/40 hover:text-foreground'
                    }`}
                  >
                    {svc.icon}
                    {svc.label}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Scan Button */}
          <button
            type="submit"
            disabled={!canScan}
            className="mt-6 flex w-full items-center justify-center gap-2 rounded-xl bg-primary px-4 py-3 text-sm font-semibold text-primary-foreground transition-all hover:opacity-90 disabled:opacity-40 disabled:cursor-not-allowed glow-primary"
          >
            {isScanning ? (
              <>
                <Loader2 size={18} className="animate-spin" />
                Scanning...
              </>
            ) : (
              'Start Security Scan'
            )}
          </button>
        </form>
      </div>
    </motion.div>
  );
}
