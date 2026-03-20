import { useState, useEffect } from 'react';
import { Shield, Server, Database, User, Network, HardDrive, Image, Globe, Eye, EyeOff, ChevronDown, ChevronUp, Loader2, Scan } from 'lucide-react';
import { motion } from 'framer-motion';
import { LLMProvider, ServiceType } from '@/lib/types';
import { loadCredentials, storeCredentials, StoredConfig } from '@/lib/credential-store';

const AWS_REGIONS = [
  'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
  'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1',
  'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-south-1',
];

const SERVICES: { id: ServiceType; label: string; icon: React.ReactNode }[] = [
  { id: 'ec2', label: 'EC2', icon: <Server size={18} /> },
  { id: 's3', label: 'S3', icon: <Database size={18} /> },
  { id: 'iam', label: 'IAM', icon: <User size={18} /> },
  { id: 'vpc', label: 'VPC', icon: <Network size={18} /> },
  { id: 'rds', label: 'RDS', icon: <Database size={18} /> },
  { id: 'ebs', label: 'EBS', icon: <HardDrive size={18} /> },
  { id: 'ami', label: 'AMI', icon: <Image size={18} /> },
  { id: 'elb', label: 'ELB', icon: <Globe size={18} /> },
];

const LLM_PROVIDERS: { id: LLMProvider; label: string }[] = [
  { id: 'codex', label: 'Codex' },
  { id: 'claude', label: 'Claude' },
  { id: 'auto', label: 'Auto Detect' },
];

type CredentialMode = 'keys' | 'profile';

interface ScanConfigProps {
  onStartScan: (config: {
    accessKey: string;
    secretKey: string;
    region: string;
    sessionToken: string | null;
    services: ServiceType[];
    llmProvider: LLMProvider;
    profile: string | null;
    credentialMode: CredentialMode;
  }) => void;
  isScanning: boolean;
  backendOnline: boolean | null;
  historySlot?: React.ReactNode;
}

export default function ScanConfiguration({ onStartScan, isScanning, backendOnline, historySlot }: ScanConfigProps) {
  const [credentialMode, setCredentialMode] = useState<CredentialMode>('keys');
  const [accessKey, setAccessKey] = useState('');
  const [secretKey, setSecretKey] = useState('');
  const [region, setRegion] = useState('us-east-1');
  const [llmProvider, setLlmProvider] = useState<LLMProvider>('codex');
  const [sessionToken, setSessionToken] = useState('');
  const [profileName, setProfileName] = useState('default');
  const [showSecret, setShowSecret] = useState(false);
  const [showSessionToken, setShowSessionToken] = useState(false);
  const [selectedServices, setSelectedServices] = useState<ServiceType[]>([]);

  useEffect(() => {
    const saved = loadCredentials();
    if (saved) {
      setCredentialMode(saved.credentialMode || 'keys');
      setAccessKey(saved.accessKey || '');
      setSecretKey(saved.secretKey || '');
      setRegion(saved.region || 'us-east-1');
      setLlmProvider(saved.llmProvider || 'codex');
      setSessionToken(saved.sessionToken || '');
      setProfileName(saved.profile || 'default');
    }
  }, []);

  const toggleService = (id: ServiceType) => {
    setSelectedServices(prev =>
      prev.includes(id) ? prev.filter(s => s !== id) : [...prev, id]
    );
  };

  const canScan =
    selectedServices.length > 0 &&
    !isScanning &&
    (credentialMode === 'profile'
      ? profileName.trim().length > 0
      : accessKey.trim().length > 0 && secretKey.trim().length > 0);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!canScan) return;

    const config: StoredConfig = {
      accessKey: credentialMode === 'keys' ? accessKey : '',
      secretKey: credentialMode === 'keys' ? secretKey : '',
      sessionToken: credentialMode === 'keys' ? sessionToken : '',
      region,
      llmProvider,
      profile: credentialMode === 'profile' ? profileName : undefined,
      credentialMode,
    };
    storeCredentials(config);

    onStartScan({
      accessKey,
      secretKey,
      region,
      sessionToken: sessionToken.trim() || null,
      services: selectedServices,
      llmProvider,
      profile: credentialMode === 'profile' ? profileName.trim() : null,
      credentialMode,
    });
  };

  const inputClass =
    'w-full rounded-xl glass-input px-4 py-3 font-mono text-sm text-foreground placeholder:text-foreground/40 focus:outline-none focus:ring-2 focus:ring-primary/40 transition-all';

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      transition={{ duration: 0.4 }}
    >
      {/* Header */}
      <div className="mb-8 text-center">
        <motion.div
          initial={{ scale: 0.8, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ delay: 0.1, duration: 0.5 }}
          className="mb-4 flex items-center justify-center gap-3"
        >
          <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-primary/12 glow-primary-soft">
            <Shield className="text-primary" size={26} />
          </div>
          <h1 className="text-3xl font-extrabold tracking-tight">
            <span className="text-gradient">CloudSentinel</span>
          </h1>
        </motion.div>
        <p className="text-sm text-foreground/60">AI-powered AWS security analysis</p>
        <div className="mt-2.5 flex items-center justify-center gap-2 text-xs">
          <span className={`h-1.5 w-1.5 rounded-full ${backendOnline === true ? 'bg-health-secure' : backendOnline === false ? 'bg-severity-critical' : 'bg-muted-foreground/30'}`} />
          <span className="text-foreground/50">
            {backendOnline === true ? 'Backend connected' : backendOnline === false ? 'Backend offline' : 'Checking...'}
          </span>
        </div>
      </div>

      {/* Form Card */}
      <div className="relative">
        {/* History panel floats to the right of the form card */}
        {historySlot && (
          <div className="hidden lg:block absolute left-[calc(100%+2rem)] top-0 w-72">
            {historySlot}
          </div>
        )}
      <form onSubmit={handleSubmit} className="glass rounded-2xl p-6">
        {/* Credential Mode Toggle */}
        <div className="mb-5">
          <label className="mb-2 block text-[11px] font-semibold text-foreground/50 uppercase tracking-[0.15em]">
            Authentication
          </label>
          <div className="flex rounded-xl overflow-hidden glass-input">
            <button
              type="button"
              onClick={() => setCredentialMode('keys')}
              className={`flex-1 px-4 py-2.5 text-xs font-semibold transition-all ${
                credentialMode === 'keys'
                  ? 'bg-[hsl(200_90%_50%)] text-white'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              AWS Keys
            </button>
            <button
              type="button"
              onClick={() => setCredentialMode('profile')}
              className={`flex-1 px-4 py-2.5 text-xs font-semibold transition-all ${
                credentialMode === 'profile'
                  ? 'bg-[hsl(200_90%_50%)] text-white'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              AWS Profile
            </button>
          </div>
        </div>

        {/* Credential Fields */}
        <div className="space-y-3.5">
          {credentialMode === 'keys' ? (
            <>
              <div>
                <label className="mb-1.5 block text-[11px] font-semibold text-foreground/50 uppercase tracking-[0.15em]">
                  Access Key ID
                </label>
                <input
                  type="text"
                  value={accessKey}
                  onChange={e => setAccessKey(e.target.value)}
                  placeholder="AKIA..."
                  className={inputClass}
                />
              </div>

              <div>
                <label className="mb-1.5 block text-[11px] font-semibold text-foreground/50 uppercase tracking-[0.15em]">
                  Secret Access Key
                </label>
                <div className="relative">
                  <input
                    type={showSecret ? 'text' : 'password'}
                    value={secretKey}
                    onChange={e => setSecretKey(e.target.value)}
                    placeholder="Enter secret key"
                    className={`${inputClass} pr-11`}
                  />
                  <button
                    type="button"
                    onClick={() => setShowSecret(!showSecret)}
                    className="absolute right-3.5 top-1/2 -translate-y-1/2 text-foreground/50 hover:text-foreground transition-colors"
                  >
                    {showSecret ? <EyeOff size={15} /> : <Eye size={15} />}
                  </button>
                </div>
              </div>
            </>
          ) : (
            <div>
              <label className="mb-1.5 block text-[11px] font-semibold text-foreground/50 uppercase tracking-[0.15em]">
                Profile Name
              </label>
              <input
                type="text"
                value={profileName}
                onChange={e => setProfileName(e.target.value)}
                placeholder="default"
                className={inputClass}
              />
              <p className="mt-1.5 text-[10px] text-foreground/40">
                Uses ~/.aws/credentials on the server
              </p>
            </div>
          )}

          {/* Region + Provider */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="mb-1.5 block text-[11px] font-semibold text-foreground/50 uppercase tracking-[0.15em]">
                Region
              </label>
              <select value={region} onChange={e => setRegion(e.target.value)} className={inputClass}>
                {AWS_REGIONS.map(r => <option key={r} value={r}>{r}</option>)}
              </select>
            </div>
            <div>
              <label className="mb-1.5 block text-[11px] font-semibold text-foreground/50 uppercase tracking-[0.15em]">
                AI Provider
              </label>
              <select value={llmProvider} onChange={e => setLlmProvider(e.target.value as LLMProvider)} className={`${inputClass} font-sans`}>
                {LLM_PROVIDERS.map(p => <option key={p.id} value={p.id}>{p.label}</option>)}
              </select>
            </div>
          </div>

          {/* Session Token */}
          {credentialMode === 'keys' && (
            <div>
              <button
                type="button"
                onClick={() => setShowSessionToken(!showSessionToken)}
                className="flex items-center gap-1.5 text-[10px] text-foreground/40 hover:text-foreground transition-colors"
              >
                {showSessionToken ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
                Optional: Session Token
              </button>
              {showSessionToken && (
                <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} className="mt-2">
                  <textarea
                    value={sessionToken}
                    onChange={e => setSessionToken(e.target.value)}
                    placeholder="Paste session token..."
                    rows={2}
                    className={`${inputClass} resize-none text-xs`}
                  />
                </motion.div>
              )}
            </div>
          )}
        </div>

        {/* Service Selector */}
        <div className="mt-6">
          <label className="mb-2.5 block text-[11px] font-semibold text-foreground/50 uppercase tracking-[0.15em]">
            Services to Scan
            {selectedServices.length > 0 && (
              <span className="ml-2 text-[hsl(200_90%_60%)] font-bold">{selectedServices.length} selected</span>
            )}
          </label>
          <div className="grid grid-cols-4 gap-2">
            {SERVICES.map(svc => {
              const selected = selectedServices.includes(svc.id);
              return (
                <button
                  key={svc.id}
                  type="button"
                  onClick={() => toggleService(svc.id)}
                  className={`flex flex-col items-center gap-1.5 rounded-xl px-3 py-3 text-xs font-semibold transition-all ${
                    selected
                      ? 'bg-[hsl(200_90%_50%/0.12)] text-[hsl(200_90%_65%)] border border-[hsl(200_90%_50%/0.3)] shadow-[0_0_12px_-3px_hsl(200_90%_50%/0.25)]'
                      : 'glass-subtle text-foreground/60 hover:text-foreground card-hover'
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
          className="mt-6 flex w-full items-center justify-center gap-2.5 rounded-xl bg-gradient-to-r from-primary to-[hsl(230_80%_60%)] px-4 py-3.5 text-sm font-bold text-white transition-all hover:brightness-110 disabled:opacity-25 disabled:cursor-not-allowed glow-primary"
        >
          {isScanning ? (
            <>
              <Loader2 size={17} className="animate-spin" />
              Scanning...
            </>
          ) : (
            <>
              <Scan size={17} />
              Start Security Scan
            </>
          )}
        </button>
      </form>
      </div>
    </motion.div>
  );
}
