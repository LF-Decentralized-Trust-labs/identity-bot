const HEALTH_URL = "http://127.0.0.1:5050/api/health";
const CACHE_KEY = "ia_agent_detected";

export async function detectLocalAgent(timeoutMs = 200): Promise<boolean> {
  const cached = sessionStorage.getItem(CACHE_KEY);
  if (cached === "true") return true;
  if (cached === "false") return false;

  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    const resp = await fetch(HEALTH_URL, { signal: ctrl.signal, mode: "cors" });
    clearTimeout(timer);
    const ok = resp.ok;
    sessionStorage.setItem(CACHE_KEY, ok ? "true" : "false");
    return ok;
  } catch {
    sessionStorage.setItem(CACHE_KEY, "false");
    return false;
  }
}

export function openDesktopLoginDeepLink(params: {
  siteAid: string;
  sessionToken: string;
  serverOobiUrl: string;
  rpSessionUrl: string;
}): void {
  const q = new URLSearchParams({
    site: params.siteAid,
    session: params.sessionToken,
    server: params.serverOobiUrl,
    rp: params.rpSessionUrl,
  });
  window.location.href = `identityagent://login?${q.toString()}`;
}

export async function triggerLocalLogin(params: {
  sessionToken: string;
  rpBaseUrl: string;
}): Promise<boolean> {
  try {
    const resp = await fetch("http://127.0.0.1:5050/api/login/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        session_token: params.sessionToken,
        rp_session_url: params.rpBaseUrl,
      }),
    });
    return resp.ok;
  } catch {
    return false;
  }
}