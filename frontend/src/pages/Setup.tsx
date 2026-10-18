import { ArrowRight, Lock, ShieldCheck, User } from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { type FormEvent, useState } from "react";
import { useNavigate } from "react-router";
import { Logo } from "../components/Shell";
import { Spinner } from "../components/ui";
import { api } from "../lib/api";

/** First run: no admin configured anywhere yet, so the first visitor creates one. */
export default function SetupPage({ onDone }: { onDone: () => Promise<unknown> }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState(false);
  const nav = useNavigate();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (password !== confirm) return setError("Passwords don't match");
    setBusy(true);
    setError(null);
    try {
      await api("/auth/setup", { method: "POST", body: { username, password } });
      setCreated(true);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const finish = async (to: string) => {
    if (to !== "/") return window.location.replace(to); // fresh load: the router re-reads /auth/me
    await onDone();
    nav(to, { replace: true });
  };

  return (
    <div className="relative grid h-full place-items-center overflow-auto px-4 py-8">
      <div aria-hidden className="bg-grid pointer-events-none absolute inset-0" />
      <motion.div initial={{ opacity: 0, y: 20, scale: 0.97 }} animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.6, ease: [0.2, 0.7, 0.2, 1] }}
        className="panel panel-brackets relative w-full max-w-sm p-8">
        <div className="mb-6 flex flex-col items-center gap-3 text-center">
          <Logo size={56} />
          <div>
            <h1 className="grad-text text-2xl font-bold tracking-tight">Welcome to NetworkVision</h1>
            <p className="mt-1 text-sm text-dim">{created ? "Your admin account is ready." : "Create your admin account to get started."}</p>
          </div>
        </div>
        <AnimatePresence mode="wait">
          {!created ? (
            <motion.form key="account" onSubmit={submit} className="space-y-4" exit={{ opacity: 0, x: -20 }}>
              <label className="relative block">
                <User size={16} className="absolute top-1/2 left-3 -translate-y-1/2 text-faint" />
                <input className="input !pl-9" value={username} onChange={(e) => setUsername(e.target.value)} aria-label="Username"
                  autoComplete="username" placeholder="Username" required maxLength={64} pattern="[A-Za-z0-9._@\-]+"
                  title="Letters, digits and . _ @ - only" />
              </label>
              <label className="relative block">
                <Lock size={16} className="absolute top-1/2 left-3 -translate-y-1/2 text-faint" />
                <input className="input !pl-9" type="password" value={password} onChange={(e) => setPassword(e.target.value)} aria-label="Password"
                  autoComplete="new-password" placeholder="Password (8+ characters)" minLength={8} autoFocus required />
              </label>
              <label className="relative block">
                <Lock size={16} className="absolute top-1/2 left-3 -translate-y-1/2 text-faint" />
                <input className="input !pl-9" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} aria-label="Confirm password"
                  autoComplete="new-password" placeholder="Confirm password" minLength={8} required />
              </label>
              {error && <div className="rounded-lg border border-crit/40 bg-crit/10 px-3 py-2 text-sm text-crit">{error}</div>}
              <button className="btn btn-primary h-11 w-full justify-center" disabled={busy}>
                {busy ? <Spinner /> : <>Create account <ArrowRight size={16} /></>}
              </button>
              <p className="text-[11.5px] text-faint">
                This page only appears until an admin exists. Forgot the password later? Set <code>NV_ADMIN_PASSWORD</code> in the
                config file and restart: it takes precedence.
              </p>
            </motion.form>
          ) : (
            <motion.div key="mfa" className="space-y-5" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }}>
              <div className="flex flex-col items-center gap-2 text-center">
                <div className="grid h-11 w-11 place-items-center rounded-xl border border-cyan/40 bg-cyan/10 text-cyan">
                  <ShieldCheck size={22} />
                </div>
                <div className="font-medium">Turn on two-factor authentication?</div>
                <div className="text-xs text-dim">Recommended: sign-ins then also need a code from an authenticator app. You can do this later under Integrations &gt; Security.</div>
              </div>
              <button className="btn btn-primary h-11 w-full justify-center" onClick={() => finish("/integrations?tab=security")}>
                Set up two-factor now
              </button>
              <button className="btn h-11 w-full justify-center" onClick={() => finish("/")}>Skip for now</button>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>
    </div>
  );
}
