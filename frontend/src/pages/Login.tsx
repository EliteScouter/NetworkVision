import { ArrowRight, Lock, User } from "lucide-react";
import { motion } from "motion/react";
import { type FormEvent, useState } from "react";
import { Logo } from "../components/Shell";
import { Spinner } from "../components/ui";
import { api } from "../lib/api";

export default function LoginPage({ configured, onLogin }: { configured: boolean; onLogin: () => void }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api("/auth/login", { method: "POST", body: { username, password } });
      onLogin();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="relative grid h-full place-items-center overflow-hidden px-4">
      <div aria-hidden className="pointer-events-none absolute inset-0">
        <div className="bg-grid absolute inset-0" />
        {[340, 520, 720, 940].map((s, i) => (
          <motion.div key={s} className="absolute top-1/2 left-1/2 rounded-full border border-cyan/10"
            style={{ width: s, height: s, marginLeft: -s / 2, marginTop: -s / 2 }}
            animate={{ rotate: i % 2 ? -360 : 360 }} transition={{ duration: 60 + i * 30, repeat: Infinity, ease: "linear" }}>
            <span className="absolute -top-1 left-1/2 h-2 w-2 rounded-full bg-cyan shadow-[0_0_14px_#22d3ee]" />
          </motion.div>
        ))}
        <div className="absolute inset-0 bg-[radial-gradient(600px_400px_at_50%_50%,rgba(34,211,238,0.10),transparent_70%)]" />
      </div>

      <motion.div initial={{ opacity: 0, y: 20, scale: 0.97 }} animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.6, ease: [0.2, 0.7, 0.2, 1] }}
        className="panel panel-brackets relative w-full max-w-sm p-8">
        <div className="mb-8 flex flex-col items-center gap-3 text-center">
          <Logo size={56} />
          <div>
            <h1 className="grad-text text-3xl font-bold tracking-tight">NetworkVision</h1>
            <p className="hud-label mt-1">Network operations center</p>
          </div>
        </div>
        {!configured ? (
          <div className="rounded-lg border border-warn/40 bg-warn/10 p-3 text-sm text-warn">
            No admin password is configured. Set <code className="font-mono">NV_ADMIN_PASSWORD</code> (or{" "}
            <code className="font-mono">NV_ADMIN_PASSWORD_HASH</code>) in your environment and restart the container.
          </div>
        ) : (
          <form onSubmit={submit} className="space-y-4">
            <label className="relative block">
              <User size={16} className="absolute top-1/2 left-3 -translate-y-1/2 text-faint" />
              <input className="input !pl-9" value={username} onChange={(e) => setUsername(e.target.value)}
                autoComplete="username" placeholder="Username" required />
            </label>
            <label className="relative block">
              <Lock size={16} className="absolute top-1/2 left-3 -translate-y-1/2 text-faint" />
              <input className="input !pl-9" type="password" value={password} onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password" placeholder="Password" autoFocus required />
            </label>
            {error && (
              <motion.div initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: [0, -6, 6, -3, 0] }}
                className="rounded-lg border border-crit/40 bg-crit/10 px-3 py-2 text-sm text-crit">
                {error}
              </motion.div>
            )}
            <button className="btn btn-primary h-11 w-full justify-center" disabled={busy}>
              {busy ? <Spinner /> : <>Engage <ArrowRight size={16} /></>}
            </button>
          </form>
        )}
      </motion.div>
    </div>
  );
}
