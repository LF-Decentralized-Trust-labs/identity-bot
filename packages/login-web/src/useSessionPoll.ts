import { useCallback, useEffect, useRef, useState } from "react";

export type PollState =
  | "idle"
  | "connecting"
  | "awaiting_approval"
  | "verified"
  | "declined"
  | "expired"
  | "error";

export interface SessionPollOptions {
  intervalMs?: number;
  /** Handed back when this browser created the session. Without it the Identity
   *  Agent reports the state but withholds who signed in, so a bystander who
   *  photographed the QR code learns nothing about the person. */
  collectorSecret?: string | null;
}

export function useSessionPoll(
  sessionEndpoint: string,
  sessionToken: string | null,
  opts: number | SessionPollOptions = 1500,
): { state: PollState; appSessionToken?: string; error?: string } {
  const { intervalMs = 1500, collectorSecret = null } =
    typeof opts === "number" ? { intervalMs: opts } : opts;
  const [state, setState] = useState<PollState>("idle");
  const [appSessionToken, setAppSessionToken] = useState<string | undefined>();
  const [error, setError] = useState<string | undefined>();
  const timer = useRef<ReturnType<typeof setInterval>>();

  const poll = useCallback(async () => {
    if (!sessionToken) return;
    try {
      const resp = await fetch(`${sessionEndpoint}/${sessionToken}`, {
        headers: collectorSecret ? { "X-Collector-Secret": collectorSecret } : undefined,
      });
      if (!resp.ok) {
        setState("error");
        setError(`poll ${resp.status}`);
        return;
      }
      const data = await resp.json();
      const s = data.state as string;
      if (s === "verified") {
        setState("verified");
        if (data.app_session_token) setAppSessionToken(data.app_session_token);
        if (timer.current) clearInterval(timer.current);
      } else if (s === "declined") {
        setState("declined");
        if (timer.current) clearInterval(timer.current);
      } else if (s === "expired") {
        setState("expired");
        if (timer.current) clearInterval(timer.current);
      } else if (s === "connected" || s === "scanned") {
        setState("awaiting_approval");
      } else {
        setState("connecting");
      }
    } catch (e) {
      setState("error");
      setError((e as Error).message);
    }
  }, [sessionEndpoint, sessionToken, collectorSecret]);

  useEffect(() => {
    if (!sessionToken) return;
    setState("connecting");
    poll();
    timer.current = setInterval(poll, intervalMs);
    return () => {
      if (timer.current) clearInterval(timer.current);
    };
  }, [sessionToken, poll, intervalMs]);

  return { state, appSessionToken, error };
}