'use client';
import { useCallback, useEffect, useState } from 'react';
import { api } from '@/services/api';

export function useLoad<T>(path: string | null, interval = 0) {
  const [result, setResult] = useState<{path: string; value: T} | null>(null);
  const [failure, setFailure] = useState<{path: string; message: string} | null>(null);
  const [revision, setRevision] = useState(0);
  const refresh = useCallback(() => setRevision(v => v + 1), []);
  useEffect(() => {
    if (!path) return;
    const controller = new AbortController(); let active = true; let pending = false;
    async function load() {
      if (pending) return; pending = true;
      try { const value = await api<T>(path!, {signal: controller.signal}); if (active) {setResult({path: path!, value}); setFailure(null);} }
      catch(e) {if (active) setFailure({path: path!, message: (e as Error).message});}
      finally {pending = false;}
    }
    load(); const timer = interval ? setInterval(load, interval) : null;
    return () => { active = false; controller.abort(); if(timer) clearInterval(timer); };
  }, [path, interval, revision]);
  const data = result?.path === path ? result.value : null;
  const error = failure?.path === path ? failure.message : '';
  return {data, error, loading: !!path && !data && !error, refresh};
}
