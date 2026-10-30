import { useEffect, useRef } from 'react';
import { createAutoRefresh } from './auto-refresh.js';

export function useAutoRefresh(task, { enabled = true, interval = 15000, dependencies = [] } = {}) {
  const latest = useRef(task); latest.current = task;
  useEffect(() => {
    if (!enabled) return;
    return createAutoRefresh(signal => latest.current(signal), { interval });
  }, [enabled, interval, ...dependencies]);
}
