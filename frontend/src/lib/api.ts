export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

type Query = Record<string, string | number | boolean | null | undefined | (string | number)[]>;

function qs(query?: Query): string {
  if (!query) return "";
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined || v === null || v === "") continue;
    if (Array.isArray(v)) v.forEach((x) => p.append(k, String(x)));
    else p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : "";
}

let onUnauthorized: (() => void) | null = null;
export const setUnauthorizedHandler = (fn: () => void) => (onUnauthorized = fn);

export async function api<T = unknown>(
  path: string,
  opts: { method?: string; body?: unknown; query?: Query; signal?: AbortSignal } = {},
): Promise<T> {
  const res = await fetch(`/api${path}${qs(opts.query)}`, {
    method: opts.method ?? "GET",
    credentials: "same-origin",
    headers: opts.body !== undefined ? { "Content-Type": "application/json" } : undefined,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    signal: opts.signal,
  });
  if (res.status === 401 && !path.startsWith("/auth/")) onUnauthorized?.();
  if (!res.ok) {
    let msg = res.statusText;
    try {
      const j = await res.json();
      msg =
        typeof j.detail === "string"
          ? j.detail
          : Array.isArray(j.detail)
            ? j.detail.map((d: { loc?: string[]; msg: string }) => `${d.loc?.slice(1).join(".")}: ${d.msg}`).join("; ")
            : msg;
    } catch {
      /* not json */
    }
    throw new ApiError(res.status, msg);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}
