import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./api";

/** Fetch JSON, optionally re-polling every `interval` ms. */
type ApiQuery = NonNullable<Parameters<typeof api>[1]>["query"];

export function useApi<T>(path: string | null, interval?: number, query?: ApiQuery) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const key = path ? path + JSON.stringify(query ?? {}) : null;
  const queryRef = useRef(query);
  queryRef.current = query;

  const load = useCallback(async () => {
    if (!path) return;
    try {
      const r = await api<T>(path, { query: queryRef.current });
      setData(r);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  useEffect(() => {
    setLoading(true);
    load();
    if (!interval) return;
    const t = window.setInterval(() => document.visibilityState === "visible" && load(), interval);
    return () => window.clearInterval(t);
  }, [load, interval]);

  return { data, error, loading, reload: load, setData };
}

export function useSize<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  const [size, setSize] = useState({ width: 0, height: 0 });
  useEffect(() => {
    if (!ref.current) return;
    const ro = new ResizeObserver(([e]) => {
      const { width, height } = e.contentRect;
      setSize((s) => (Math.abs(s.width - width) > 0.5 || Math.abs(s.height - height) > 0.5 ? { width, height } : s));
    });
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);
  return [ref, size] as const;
}

/** Re-render every `ms` so "x seconds ago" labels stay fresh. */
export function useTick(ms = 1000) {
  const [, setN] = useState(0);
  useEffect(() => {
    const t = window.setInterval(() => setN((n) => n + 1), ms);
    return () => window.clearInterval(t);
  }, [ms]);
}

export function useReducedMotion() {
  const [r, setR] = useState(() => window.matchMedia("(prefers-reduced-motion: reduce)").matches);
  useEffect(() => {
    const m = window.matchMedia("(prefers-reduced-motion: reduce)");
    const fn = () => setR(m.matches);
    m.addEventListener("change", fn);
    return () => m.removeEventListener("change", fn);
  }, []);
  return r;
}

export function useLocalState<T>(key: string, initial: T) {
  const [v, setV] = useState<T>(() => {
    try {
      const raw = localStorage.getItem(`nv:${key}`);
      return raw ? (JSON.parse(raw) as T) : initial;
    } catch {
      return initial;
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem(`nv:${key}`, JSON.stringify(v));
    } catch {
      /* storage unavailable */
    }
  }, [key, v]);
  return [v, setV] as const;
}
