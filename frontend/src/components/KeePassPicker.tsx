import { KeyRound, Search } from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../lib/api";
import { Spinner } from "./ui";

type Entry = { ref: string; title: string; group: string; has_username: boolean; has_password: boolean; custom_fields: string[] };

/** Button + popover that inserts a kp:Group/Entry[#field] reference. Shows names only, never secret values. */
export function KeePassPicker({ onPick }: { onPick: (ref: string) => void }) {
  const [open, setOpen] = useState(false);
  const [entries, setEntries] = useState<Entry[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const box = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open || entries) return;
    api<{ entries: Entry[] }>("/keepass/entries").then((r) => setEntries(r.entries)).catch((e) => setErr((e as Error).message));
  }, [open, entries]);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => box.current && !box.current.contains(e.target as Node) && setOpen(false);
    window.addEventListener("mousedown", close);
    return () => window.removeEventListener("mousedown", close);
  }, [open]);

  const shown = useMemo(() => (entries ?? []).filter((e) => !q || e.ref.toLowerCase().includes(q.toLowerCase())), [entries, q]);
  const pick = (ref: string) => { onPick(`kp:${ref}`); setOpen(false); };

  return (
    <div ref={box} className="relative">
      <button type="button" title="Pick from KeePass" onClick={() => setOpen(!open)}
        className="btn h-[38px] !px-2.5 text-violet hover:!border-violet/50">
        <KeyRound size={15} />
      </button>
      <AnimatePresence>
        {open && (
          <motion.div initial={{ opacity: 0, y: -4, scale: 0.98 }} animate={{ opacity: 1, y: 0, scale: 1 }} exit={{ opacity: 0, y: -4 }}
            className="panel absolute top-11 right-0 z-30 w-80 overflow-hidden !rounded-xl shadow-2xl">
            <div className="flex items-center gap-2 border-b border-edge px-3 py-2">
              <Search size={14} className="text-faint" />
              <input autoFocus value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search KeePass entries…"
                className="flex-1 bg-transparent text-sm outline-none" />
            </div>
            <div className="max-h-72 overflow-y-auto p-1.5">
              {err && <div className="p-3 text-xs text-crit">{err}</div>}
              {!entries && !err && <div className="flex justify-center p-4"><Spinner /></div>}
              {entries && !shown.length && <div className="p-3 text-center text-xs text-faint">No entries match.</div>}
              {shown.map((e) => (
                <div key={e.ref} className="rounded-lg px-2.5 py-2 hover:bg-white/[0.03]">
                  <div className="truncate text-sm">{e.title}{e.group && <span className="text-faint"> · {e.group}</span>}</div>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {e.has_password && <FieldChip onClick={() => pick(e.ref)}>password</FieldChip>}
                    {e.has_username && <FieldChip onClick={() => pick(`${e.ref}#username`)}>username</FieldChip>}
                    {e.custom_fields.map((f) => <FieldChip key={f} onClick={() => pick(`${e.ref}#${f}`)}>{f}</FieldChip>)}
                  </div>
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function FieldChip({ children, onClick }: { children: React.ReactNode; onClick: () => void }) {
  return (
    <button type="button" onClick={onClick}
      className="rounded-md border border-violet/30 bg-violet/10 px-1.5 py-0.5 font-mono text-[10.5px] text-violet hover:bg-violet/20">
      {children}
    </button>
  );
}
