import { Copy, Download, KeyRound, Lock, RefreshCw, ShieldCheck, ShieldOff, Smartphone } from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { useState } from "react";
import { api } from "../lib/api";
import { clock } from "../lib/format";
import { useApi } from "../lib/hooks";
import { Badge, Field, Kv, Panel, Spinner } from "./ui";

type MfaStatus = {
  enabled: boolean;
  source: "env" | "database" | null;
  managed_by_env: boolean;
  recovery_codes_remaining: number | null;
  enabled_at: number | null;
  error: string | null;
};
type Setup = { secret: string; otpauth_uri: string; qr_svg: string };
export type KeePassStatus = {
  configured: boolean;
  ok?: boolean;
  error?: string | null;
  file?: string;
  entries?: number;
  loaded_at?: number | null;
  keyfile?: boolean;
};

function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const [copied, setCopied] = useState(false);
  const text = `NetworkVision recovery codes (each works once)\n\n${codes.join("\n")}\n`;
  const download = () => {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    a.download = "networkvision-recovery-codes.txt";
    a.click();
    URL.revokeObjectURL(a.href);
  };
  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-3">
      <div className="rounded-lg border border-warn/40 bg-warn/10 p-3 text-sm text-warn">
        Save these recovery codes somewhere safe (your KeePass vault is perfect). Each one signs you in once if you lose your phone.
        <b> They won't be shown again.</b>
      </div>
      <div className="grid grid-cols-2 gap-2 rounded-xl border border-edge bg-black/30 p-4 font-mono text-sm tracking-wider">
        {codes.map((c) => <span key={c}>{c}</span>)}
      </div>
      <div className="flex flex-wrap gap-2">
        <button className="btn" onClick={() => { navigator.clipboard?.writeText(text); setCopied(true); }}>
          <Copy size={14} /> {copied ? "Copied" : "Copy"}
        </button>
        <button className="btn" onClick={download}><Download size={14} /> Download .txt</button>
        <button className="btn btn-primary ml-auto" onClick={onDone}>I've saved them</button>
      </div>
    </motion.div>
  );
}

function ReauthForm({ label, danger, onSubmit }: { label: string; danger?: boolean; onSubmit: (password: string, code: string) => Promise<void> }) {
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  return (
    <form className="space-y-3" onSubmit={async (e) => {
      e.preventDefault();
      setBusy(true); setErr(null);
      try { await onSubmit(password, code); } catch (x) { setErr((x as Error).message); } finally { setBusy(false); }
    }}>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Current password"><input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required /></Field>
        <Field label="Authenticator or recovery code"><input className="input num tracking-widest" value={code} onChange={(e) => setCode(e.target.value.trim())} inputMode="numeric" autoComplete="one-time-code" required minLength={6} /></Field>
      </div>
      {err && <div className="text-sm text-crit">{err}</div>}
      <button className={danger ? "btn btn-danger" : "btn btn-primary"} disabled={busy}>{busy ? <Spinner size={14} /> : null}{label}</button>
    </form>
  );
}

export function AccountSecurity({ keepass, sso }: { keepass: KeePassStatus | null; sso: boolean }) {
  const { data: st, reload } = useApi<MfaStatus>("/auth/mfa/status");
  const [setup, setSetup] = useState<Setup | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [mode, setMode] = useState<"" | "disable" | "regen">("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [showSecret, setShowSecret] = useState(false);

  const start = async () => {
    setBusy(true); setErr(null);
    try { setSetup(await api<Setup>("/auth/mfa/setup", { method: "POST" })); } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Panel title="Two-factor authentication" icon={<ShieldCheck size={15} />}>
        {!st ? <Spinner /> : (
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <div className={`grid h-11 w-11 place-items-center rounded-xl border ${st.enabled ? "border-ok/40 bg-ok/10 text-ok" : "border-warn/40 bg-warn/10 text-warn"}`}>
                {st.enabled ? <ShieldCheck size={22} /> : <ShieldOff size={22} />}
              </div>
              <div>
                <div className="font-medium">{st.enabled ? "MFA is on" : "MFA is off"}</div>
                <div className="text-xs text-dim">
                  {st.managed_by_env ? "Pinned by NV_ADMIN_TOTP_SECRET (manage it in your stack env)"
                    : st.enabled ? `Enabled ${st.enabled_at ? clock(st.enabled_at, true) : ""} · ${st.recovery_codes_remaining} recovery codes left`
                    : "Protect the dashboard with an authenticator app (TOTP)."}
                </div>
              </div>
              {st.enabled && <Badge tone="ok" className="ml-auto">protected</Badge>}
            </div>
            {sso && <div className="rounded-lg border border-info/30 bg-info/5 p-2.5 text-xs text-dim">You're signed in through SSO / proxy auth. MFA applies to the built-in password login.</div>}
            {st.error && <div className="rounded-lg border border-crit/40 bg-crit/10 p-2.5 text-xs text-crit">{st.error}</div>}
            {err && <div className="text-sm text-crit">{err}</div>}

            <AnimatePresence mode="wait">
              {codes ? (
                <RecoveryCodes key="codes" codes={codes} onDone={() => { setCodes(null); setMode(""); reload(); }} />
              ) : setup ? (
                <motion.div key="setup" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
                  <div className="flex flex-col items-center gap-4 sm:flex-row sm:items-start">
                    <img src={setup.qr_svg} alt="Scan this QR code with your authenticator app" className="h-44 w-44 rounded-xl border border-cyan/30 shadow-[0_0_30px_-10px_#22d3ee]" />
                    <ol className="list-decimal space-y-2 pl-4 text-sm text-dim">
                      <li>Scan the QR code with Google Authenticator, Authy, 1Password, Bitwarden or <b className="text-ink">KeePassXC</b>.</li>
                      <li>Enter the 6-digit code it shows, plus your password.</li>
                      <li>Save the recovery codes you get next.</li>
                      <li>
                        Can't scan?{" "}
                        <button className="text-cyan hover:underline" onClick={() => setShowSecret(!showSecret)}>{showSecret ? "Hide" : "Show"} the setup key</button>
                        {showSecret && <code className="mt-1 block break-all rounded bg-black/40 p-2 text-xs text-ink">{setup.secret}</code>}
                      </li>
                    </ol>
                  </div>
                  <ReauthForm label="Verify & enable" onSubmit={async (password, code) => {
                    const r = await api<{ recovery_codes: string[] }>("/auth/mfa/enable", { method: "POST", body: { password, code } });
                    setSetup(null); setCodes(r.recovery_codes);
                  }} />
                  <button className="text-xs text-dim hover:text-ink" onClick={() => setSetup(null)}>Cancel</button>
                </motion.div>
              ) : mode ? (
                <motion.div key={mode} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-2">
                  <div className="text-sm text-dim">{mode === "disable" ? "Confirm to turn MFA off. All other sessions will be signed out." : "Old recovery codes stop working immediately."}</div>
                  <ReauthForm label={mode === "disable" ? "Disable MFA" : "Generate new codes"} danger={mode === "disable"} onSubmit={async (password, code) => {
                    if (mode === "disable") {
                      await api("/auth/mfa/disable", { method: "POST", body: { password, code } });
                      setMode(""); reload();
                    } else {
                      const r = await api<{ recovery_codes: string[] }>("/auth/mfa/recovery-codes", { method: "POST", body: { password, code } });
                      setCodes(r.recovery_codes);
                    }
                  }} />
                  <button className="text-xs text-dim hover:text-ink" onClick={() => setMode("")}>Cancel</button>
                </motion.div>
              ) : (
                <motion.div key="actions" className="flex flex-wrap gap-2">
                  {!st.enabled && <button className="btn btn-primary" onClick={start} disabled={busy}>{busy ? <Spinner size={14} /> : <Smartphone size={15} />} Set up authenticator</button>}
                  {st.source === "database" && (
                    <>
                      <button className="btn" onClick={() => setMode("regen")}><RefreshCw size={14} /> New recovery codes</button>
                      <button className="btn btn-danger" onClick={() => setMode("disable")}><ShieldOff size={14} /> Disable</button>
                    </>
                  )}
                </motion.div>
              )}
            </AnimatePresence>
            <p className="text-[11.5px] text-faint">Lost your phone and your codes? Set <code>NV_MFA_RESET=true</code> in the stack, restart, sign in, then remove it and enroll again.</p>
          </div>
        )}
      </Panel>

      <Panel title="KeePass secret provider" icon={<KeyRound size={15} />}>
        {!keepass ? <Spinner /> : !keepass.configured ? (
          <div className="space-y-3 text-sm text-dim">
            <p>Keep device credentials in a KeePass database instead of NetworkVision. Reference entries in any credential field as
              <code className="mx-1 text-violet">kp:Group/Entry</code>, <code className="text-violet">kp:Group/Entry#username</code> or a custom field like
              <code className="ml-1 text-violet">kp:Group/Entry#api_key</code>.</p>
            <ol className="list-decimal space-y-1 pl-4 text-xs">
              <li>Create a <b className="text-ink">dedicated</b> .kdbx holding only NetworkVision's device credentials.</li>
              <li>Copy it to the Docker host and mount it read-only, e.g. <code>/opt/networkvision/nv.kdbx:/secrets/nv.kdbx:ro</code>.</li>
              <li>Set <code>NV_KEEPASS_FILE=/secrets/nv.kdbx</code> and <code>NV_KEEPASS_PASSWORD</code> (or <code>NV_KEEPASS_KEYFILE</code>) and redeploy.</li>
            </ol>
            <p className="text-xs text-faint">The file is re-read automatically when it changes, so rotated passwords apply on the next poll.</p>
          </div>
        ) : (
          <div>
            <div className="mb-3 flex items-center gap-2">
              <Lock size={16} className={keepass.ok ? "text-ok" : "text-crit"} />
              <span className="font-medium">{keepass.ok ? "Unlocked" : "Unavailable"}</span>
              <Badge tone={keepass.ok ? "ok" : "critical"} className="ml-auto">{keepass.ok ? "connected" : "error"}</Badge>
            </div>
            {keepass.error && <div className="mb-3 rounded-lg border border-crit/40 bg-crit/10 p-2.5 text-xs text-crit">{keepass.error}</div>}
            <Kv k="Database" v={keepass.file} />
            <Kv k="Entries" v={keepass.entries} />
            <Kv k="Unlock" v={keepass.keyfile ? "password + keyfile" : "password"} />
            <Kv k="Loaded" v={keepass.loaded_at ? clock(keepass.loaded_at, true) : "—"} />
          </div>
        )}
      </Panel>
    </div>
  );
}
