import { type ReactNode, useEffect, useLayoutEffect, useRef, useState } from "react";

/**
 * A newest-first feed that scrolls smoothly: incoming items are collected and released every
 * `every` seconds, then the whole list glides down by exactly the height of the new rows (they
 * slide in from above the clip edge). Rows are never remounted or faded, so a busy source can't
 * make the list blink, however many lines arrive per second.
 */
export function SlideList<T>({ items, keyOf, render, rowHeight, max, every = 1, resetKey }: {
  items: T[];
  keyOf: (item: T) => string | number;
  render: (item: T) => ReactNode;
  rowHeight: number;
  max: number;
  /** Seconds between updates. */
  every?: number;
  /** Changing this (e.g. a filter) shows the current items immediately, without animation. */
  resetKey?: string;
}) {
  const latest = useRef(items);
  latest.current = items;
  const [shown, setShown] = useState(() => items.slice(0, max));
  const added = useRef(0);
  const box = useRef<HTMLDivElement>(null);

  useEffect(() => {
    added.current = 0;
    setShown(latest.current.slice(0, max));
  }, [resetKey, max]);

  useEffect(() => {
    const t = window.setInterval(() => {
      if (document.visibilityState !== "visible") return;
      setShown((prev) => {
        const all = latest.current;
        const next = all.slice(0, max);
        if (!prev.length) return next;
        const head = keyOf(prev[0]);
        const i = all.findIndex((x) => keyOf(x) === head);
        if (i === 0) return prev; // nothing new
        added.current = i > 0 ? i : 0; // head gone entirely (filter / list replaced): no slide
        return next;
      });
    }, Math.max(0.3, every) * 1000);
    return () => window.clearInterval(t);
  }, [every, max, keyOf]);

  useLayoutEffect(() => {
    const n = added.current;
    added.current = 0;
    if (!n || !box.current) return;
    const dy = Math.min(n, max) * rowHeight;
    box.current.animate([{ transform: `translateY(${-dy}px)` }, { transform: "translateY(0)" }],
      { duration: Math.min(900, 300 + dy * 2), easing: "cubic-bezier(0.2, 0.7, 0.2, 1)" });
  }, [shown, max, rowHeight]);

  return (
    <div ref={box}>
      {shown.map((item) => (
        <div key={keyOf(item)} style={{ height: rowHeight }}>{render(item)}</div>
      ))}
    </div>
  );
}
