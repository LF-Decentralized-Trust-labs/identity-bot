import { useCallback, useEffect, useRef, useState } from "react";
import { readPageSession, type PageSessionRead } from "./pageSession.js";

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
  /** The fetch to read the session with; a utility app's page passes the one `appFetch` makes. */
  fetchFn?: typeof fetch;
}

export function useSessionPoll(
  sessionEndpoint: string,
  sessionToken: string | null,
  opts: number | SessionPollOptions = 1500,
): { state: PollState; appSessionToken?: string; result?: PageSessionRead; error?: string; lastRefusal?: string; reason?: string } {
  const { intervalMs = 1500, collectorSecret = null, fetchFn } =
    typeof opts === "number" ? { intervalMs: opts } : opts;
  const [state, setState] = useState<PollState>("idle");
  const [appSessionToken, setAppSessionToken] = useState<string | undefined>();
  const [result, setResult] = useState<PageSessionRead | undefined>();
  const [lastRefusal, setLastRefusal] = useState<string | undefined>();
  const [reason, setReason] = useState<string | undefined>();
  const [error, setError] = useState<string | undefined>();
  const timer = useRef<ReturnType<typeof setInterval>>();

  const poll = useCallback(async () => {
    if (!sessionToken) return;
    try {
      const data = await readPageSession({ sessionEndpoint, sessionToken, collectorSecret, fetchFn });
      const s = data.state;
      setLastRefusal(data.lastRefusal);
      setReason(data.reason);
      if (s === "verified") {
        setState("verified");
        setResult(data);
        if (data.appSessionToken) setAppSessionToken(data.appSessionToken);
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
  }, [sessionEndpoint, sessionToken, collectorSecret, fetchFn]);

  useEffect(() => {
    if (!sessionToken) return;
    setState("connecting");
    poll();
    timer.current = setInterval(poll, intervalMs);
    return () => {
      if (timer.current) clearInterval(timer.current);
    };
  }, [sessionToken, poll, intervalMs]);

  return { state, appSessionToken, result, error, lastRefusal, reason };
}