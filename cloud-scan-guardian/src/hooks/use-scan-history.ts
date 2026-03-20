import { useState, useEffect, useCallback } from 'react';
import { ScanSummary } from '@/lib/types';
import { listScans, deleteSession as apiDeleteSession } from '@/lib/api';

/**
 * Hook that fetches scan history and groups results by session_id.
 */
export function useScanHistory() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);

  const fetch_ = useCallback(async () => {
    try {
      const result = await listScans();
      setScans(result);
    } catch {
      // Backend may be offline — silently ignore
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetch_();
  }, [fetch_]);

  const refresh = useCallback(() => {
    fetch_();
  }, [fetch_]);

  const remove = useCallback(async (sessionId: string) => {
    // Optimistic delete
    setScans(prev => prev.filter(s => s.session_id !== sessionId));
    try {
      await apiDeleteSession(sessionId);
    } catch {
      // If delete fails, refresh to get real state
      fetch_();
    }
  }, [fetch_]);

  // Group by session_id, maintaining order (newest session first)
  const sessions = new Map<string, ScanSummary[]>();
  for (const scan of scans) {
    const existing = sessions.get(scan.session_id);
    if (existing) {
      existing.push(scan);
    } else {
      sessions.set(scan.session_id, [scan]);
    }
  }

  return { sessions, loading, refresh, remove };
}
