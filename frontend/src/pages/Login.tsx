import { ArrowLeft, ArrowRight, KeyRound, Lock, ShieldCheck, User } from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { type FormEvent, useEffect, useRef, useState } from "react";
import { Logo } from "../components/Shell";
import { Spinner } from "../components/ui";
import { api } from "../lib/api";

type LoginResult = { user?: string; mfa_required?: boolean; mfa_token?: string };

function CodeInput({ onComplete, disabled }: { onComplete: (code: string) => void; disabled: boolean }) {
  const [digits, setDigits] = useState<string[]>(Array(6).fill(""));
  const refs = useRef<(HTMLInputElement | null)[]>([]);
  useEffect(() => refs.current[0]?.focus(), []);

  const set = (i: number, raw: string) => {
    const chars = raw.replace(/\D/g, "").split("");
    if (!chars.length) {
      const next = [...digits];
      next[i] = "";
      setDigits(next);
      return;
    }
    const next = [...digits];
    chars.slice(0, 6 - i).forEach((c, k) => (next[i + k] = c)); // supports pasting the whole code
    setDigits(next);
    const focus = Math.min(5, i + chars.length);
    refs.current[focus]?.focus();
    if (next.every(Boolean)) onComplete(next.join(""));
  };

  return (
    <div className="flex justify-center gap-2">
      {digits.map((d, i) => (
        <input
          key={i}
          ref={(el) => { refs.current[i] = el; }}
          value={d}
          disabled={disabled}
          inputMode="numeric"
          autoComplete={i === 0 ? "one-time-code" : "off"}
          aria-label={`Digit ${i + 1}`}
          maxLength={6}
          onChange={(e) => set(i, e.target.value)}
          onKeyDown={(e) => e.key === "Backspace" && !digits[i] && i > 0 && refs.current[i - 1]?.focus()}
          className="input num h-12 !w-11 !px-0 text-center !text-xl"
        />
      ))}
    </div>
  );
}

export default function LoginPage({ configured, onLogin }: { configured: boolean; onLogin: () => void }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [recovery, setRecovery] = useState(false);
  const [recoveryCode, setRecoveryCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [attempt, setAttempt] = useState(0); // remounts the code boxes after a failure

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await api<LoginResult>("/auth/login", { method: "POST", body: { username, password } });
      if (r.mfa_required && r.mfa_token) {
        setMfaToken(r.mfa_token);
        setPassword("");
      } else onLogin();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const verify = async (code: string) => {
    if (!mfaToken) return;
    setBusy(true);
    setError(null);
    try {
      await api("/auth/mfa", { method: "POST", body: { mfa_token: mfaToken, code } });
      onLogin();
    } catch (err) {
      const msg = (err as Error).message;
      setError(msg);
      setAttempt((a) => a + 1);
      if (/expired/i.test(msg)) setMfaToken(null);
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
          <AnimatePresence mode="wait">
            {!mfaToken ? (
              <motion.form key="pw" onSubmit={submit} className="space-y-4" initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -20 }}>
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
                {error && <ErrorBox msg={error} />}
                <button className="btn btn-primary h-11 w-full justify-center" disabled={busy}>
                  {busy ? <Spinner /> : <>Engage <ArrowRight size={16} /></>}
                </button>
              </motion.form>
            ) : (
              <motion.div key="mfa" className="space-y-5" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 20 }}>
                <div className="flex flex-col items-center gap-2 text-center">
                  <div className="grid h-11 w-11 place-items-center rounded-xl border border-cyan/40 bg-cyan/10 text-cyan shadow-[0_0_20px_-6px_#22d3ee]">
                    <ShieldCheck size={22} />
                  </div>
                  <div className="font-medium">Two-factor authentication</div>
                  <div className="text-xs text-dim">
                    {recovery ? "Enter one of your recovery codes." : "Enter the 6-digit code from your authenticator app."}
                  </div>
                </div>
                {recovery ? (
                  <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); verify(recoveryCode); }}>
                    <label className="relative block">
                      <KeyRound size={16} className="absolute top-1/2 left-3 -translate-y-1/2 text-faint" />
                      <input className="input font-mono !pl-9 tracking-widest" value={recoveryCode} autoFocus placeholder="xxxxx-xxxxx"
                        onChange={(e) => setRecoveryCode(e.target.value)} autoComplete="off" spellCheck={false} />
                    </label>
                    <button className="btn btn-primary h-11 w-full justify-center" disabled={busy || recoveryCode.length < 10}>
                      {busy ? <Spinner /> : "Verify"}
                    </button>
                  </form>
                ) : (
                  <CodeInput key={attempt} onComplete={verify} disabled={busy} />
                )}
                {error && <ErrorBox msg={error} />}
                <div className="flex items-center justify-between text-xs">
                  <button className="flex items-center gap-1 text-dim hover:text-ink" onClick={() => { setMfaToken(null); setError(null); }}>
                    <ArrowLeft size={13} /> Back
                  </button>
                  <button className="text-cyan hover:underline" onClick={() => { setRecovery(!recovery); setError(null); }}>
                    {recovery ? "Use authenticator code" : "Use a recovery code"}
                  </button>
                </div>
                {busy && !recovery && <div className="flex justify-center"><Spinner /></div>}
              </motion.div>
            )}
          </AnimatePresence>
        )}
      </motion.div>
    </div>
  );
}

function ErrorBox({ msg }: { msg: string }) {
  return (
    <motion.div initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: [0, -6, 6, -3, 0] }}
      className="rounded-lg border border-crit/40 bg-crit/10 px-3 py-2 text-sm text-crit">
      {msg}
    </motion.div>
  );
}
