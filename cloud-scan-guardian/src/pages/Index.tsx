import { useState, useEffect, useCallback, useRef } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { Shield, RotateCcw } from 'lucide-react';
import { LLMProvider, ServiceType, ServiceAnalysis, SSEEvent } from '@/lib/types';
import { checkHealth, startScan } from '@/lib/api';
import ScanConfiguration from '@/components/ScanConfiguration';
import ScanProgress, { ServiceStatus } from '@/components/ScanProgress';
import ResultCard from '@/components/ResultCard';

type View = 'config' | 'scanning';

interface ServiceProgress {
  service: ServiceType;
  status: ServiceStatus;
  message: string;
}

export default function Index() {
  const [view, setView] = useState<View>('config');
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);
  const [serviceProgress, setServiceProgress] = useState<ServiceProgress[]>([]);
  const [results, setResults] = useState<Map<ServiceType, ServiceAnalysis>>(new Map());
  const [errors, setErrors] = useState<Map<ServiceType, string>>(new Map());
  const [scanDone, setScanDone] = useState(false);
  const [savedConfig, setSavedConfig] = useState<{ accessKey: string; secretKey: string; region: string; llmProvider: LLMProvider } | undefined>();
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    checkHealth()
      .then(() => setBackendOnline(true))
      .catch(() => setBackendOnline(false));
  }, []);

  const handleStartScan = useCallback((config: {
    accessKey: string;
    secretKey: string;
    region: string;
    sessionToken: string | null;
    services: ServiceType[];
    llmProvider: LLMProvider;
  }) => {
    setSavedConfig({
      accessKey: config.accessKey,
      secretKey: config.secretKey,
      region: config.region,
      llmProvider: config.llmProvider,
    });
    setView('scanning');
    setScanDone(false);
    setResults(new Map());
    setErrors(new Map());

    const progress: ServiceProgress[] = config.services.map(s => ({
      service: s, status: 'pending' as ServiceStatus, message: '',
    }));
    setServiceProgress(progress);

    const controller = new AbortController();
    abortRef.current = controller;

    const handleEvent = (event: SSEEvent) => {
      if (event.type === 'progress') {
        setServiceProgress(prev =>
          prev.map(p =>
            p.service === event.service
              ? { ...p, status: 'scanning', message: event.message }
              : p
          )
        );
      } else if (event.type === 'result') {
        setResults(prev => new Map(prev).set(event.service, event.analysis));
        setServiceProgress(prev =>
          prev.map(p =>
            p.service === event.service
              ? { ...p, status: 'done', message: 'Complete' }
              : p
          )
        );
      } else if (event.type === 'error') {
        setErrors(prev => new Map(prev).set(event.service, event.message));
        setServiceProgress(prev =>
          prev.map(p =>
            p.service === event.service
              ? { ...p, status: 'error', message: event.message }
              : p
          )
        );
      } else if (event.type === 'done') {
        setScanDone(true);
      }
    };

    startScan(
      {
        services: config.services,
        region: config.region,
        access_key: config.accessKey,
        secret_key: config.secretKey,
        session_token: config.sessionToken,
        llm_provider: config.llmProvider,
      },
      handleEvent,
      controller.signal
    ).catch(err => {
      if (err.name !== 'AbortError') {
        console.error('Scan error:', err);
        setScanDone(true);
      }
    });
  }, []);

  const handleCancel = () => {
    abortRef.current?.abort();
    setView('config');
  };

  const handleReset = () => {
    setView('config');
    setScanDone(false);
  };

  return (
    <div className="min-h-screen bg-background">
      <AnimatePresence mode="wait">
        {view === 'config' ? (
          <ScanConfiguration
            key="config"
            onStartScan={handleStartScan}
            isScanning={false}
            backendOnline={backendOnline}
            initialConfig={savedConfig}
          />
        ) : (
          <motion.div
            key="scanning"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="mx-auto max-w-4xl p-4 pt-8 space-y-6"
          >
            {/* Header */}
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10">
                <Shield className="text-primary" size={20} />
              </div>
              <h1 className="text-xl font-bold text-foreground">CloudSentinel</h1>
            </div>

            {/* Progress */}
            <ScanProgress rows={serviceProgress} onCancel={handleCancel} />

            {/* Error cards */}
            {Array.from(errors.entries()).map(([service, message]) => (
              <div key={service} className="rounded-2xl border border-[hsl(var(--severity-critical)/0.3)] bg-severity-critical/10 p-5">
                <p className="text-sm font-semibold text-severity-critical uppercase">{service} — Error</p>
                <p className="mt-1 text-xs text-muted-foreground">{message}</p>
              </div>
            ))}

            {/* Result cards */}
            {Array.from(results.entries()).map(([service, analysis]) => (
              <motion.div
                key={service}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
              >
                <ResultCard analysis={analysis} />
              </motion.div>
            ))}

            {/* Skeleton while not done */}
            {!scanDone && results.size === 0 && errors.size === 0 && (
              <div className="space-y-4">
                {[1, 2].map(i => (
                  <div key={i} className="rounded-2xl border border-border bg-card p-6 scan-pulse">
                    <div className="h-4 w-32 rounded bg-muted mb-4" />
                    <div className="space-y-2">
                      <div className="h-3 w-full rounded bg-muted" />
                      <div className="h-3 w-2/3 rounded bg-muted" />
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Scan complete */}
            {scanDone && (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="text-center pt-4">
                <button
                  onClick={handleReset}
                  className="inline-flex items-center gap-2 rounded-xl bg-primary px-6 py-3 text-sm font-semibold text-primary-foreground hover:opacity-90 transition-opacity"
                >
                  <RotateCcw size={16} />
                  Scan Another
                </button>
              </motion.div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
