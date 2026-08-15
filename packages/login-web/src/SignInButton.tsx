import React, { useCallback, useState } from "react";
import { detectLocalAgent, openDesktopLoginDeepLink, triggerLocalLogin } from "./agentDetect.js";
import { useSessionPoll } from "./useSessionPoll.js";
import { LoginQrCode } from "./LoginQrCode.js";

export interface SignInButtonProps {
  sessionEndpoint: string;
  requestDisclosures: string[];
  requestCredentials?: Array<{ schemaSaid: string; required?: boolean }>;
  requestScore?: { minBand?: "red" | "amber" | "green"; minScore?: number; required?: boolean };
  theme?: "light" | "dark" | "auto";
  size?: "small" | "medium" | "large";
  qrFallback?: boolean;
  /** `collectorSecret` must be forwarded to your own backend and passed to
   *  confirmLoginSession — the Identity Agent will not name the person without it. */
  onSuccess?: (session: {
    sessionToken: string;
    appSessionToken?: string;
    collectorSecret?: string | null;
  }) => void;
  onError?: (err: Error) => void;
}

const SIZES = {
  small: { height: 32, font: 13, logo: 20 },
  medium: { height: 40, font: 15, logo: 24 },
  large: { height: 48, font: 17, logo: 28 },
};

function IALogo({ size }: { size: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true">
      <circle cx="12" cy="12" r="10" fill="#1a56db" />
      <path d="M8 12l3 3 5-6" stroke="#fff" strokeWidth="2" fill="none" strokeLinecap="round" />
    </svg>
  );
}

export function SignInButton({
  sessionEndpoint,
  requestDisclosures,
  requestCredentials = [],
  requestScore,
  theme = "auto",
  size = "medium",
  qrFallback = true,
  onSuccess,
  onError,
}: SignInButtonProps) {
  const [sessionToken, setSessionToken] = useState<string | null>(null);
  const [collectorSecret, setCollectorSecret] = useState<string | null>(null);
  const [relayUrl, setRelayUrl] = useState<string | null>(null);
  const [qrUrl, setQrUrl] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [showQr, setShowQr] = useState(false);
  const dims = SIZES[size];
  const poll = useSessionPoll(sessionEndpoint, sessionToken, { collectorSecret });

  React.useEffect(() => {
    if (poll.state === "verified" && sessionToken) {
      onSuccess?.({ sessionToken, appSessionToken: poll.appSessionToken, collectorSecret });
    }
    if (poll.state === "declined" || poll.state === "expired" || poll.state === "error") {
      onError?.(new Error(poll.error ?? poll.state));
    }
  }, [poll.state, poll.appSessionToken, poll.error, sessionToken, collectorSecret, onSuccess, onError]);

  const startLogin = useCallback(async () => {
    setBusy(true);
    try {
      const resp = await fetch(sessionEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          requestDisclosures,
          requestCredentials: requestCredentials.map((c) => ({
            schema_said: c.schemaSaid,
            required: c.required ?? false,
          })),
          requestScore: requestScore
            ? {
                min_band: requestScore.minBand,
                min_score: requestScore.minScore,
                required: requestScore.required,
              }
            : undefined,
        }),
      });
      if (!resp.ok) throw new Error(`session create failed: ${resp.status}`);
      const data = await resp.json();
      setSessionToken(data.session_token);
      setCollectorSecret(data.collector_secret ?? null);
      setRelayUrl(data.relay_or_qr_url);
      setQrUrl(data.qr_url ?? data.relay_or_qr_url);

      if (qrFallback) {
        setShowQr(true);
      }

      const hasAgent = await detectLocalAgent();
      const rpBase = window.location.origin;
      if (hasAgent) {
        const ok = await triggerLocalLogin({
          sessionToken: data.session_token,
          rpBaseUrl: rpBase,
        });
        if (!ok) {
          openDesktopLoginDeepLink({
            siteAid: "",
            sessionToken: data.session_token,
            serverOobiUrl: data.relay_or_qr_url,
            rpSessionUrl: rpBase,
          });
        }
      }
    } catch (e) {
      onError?.(e as Error);
    } finally {
      setBusy(false);
    }
  }, [sessionEndpoint, requestDisclosures, requestCredentials, requestScore, qrFallback, onError]);

  const isDark =
    theme === "dark" ||
    (theme === "auto" && typeof window !== "undefined" && window.matchMedia("(prefers-color-scheme: dark)").matches);

  const label =
    poll.state === "awaiting_approval"
      ? "Approve in your Identity Agent"
      : busy || poll.state === "connecting"
        ? "Connecting…"
        : poll.state === "verified"
          ? "Signed in"
          : "Sign in with Identity Agent";

  return (
    <div className="ia-login-widget" data-theme={isDark ? "dark" : "light"}>
      <button
        type="button"
        onClick={startLogin}
        disabled={busy || poll.state === "verified"}
        style={{
          display: "inline-flex",
          alignItems: "center",
          gap: 8,
          height: dims.height,
          padding: "0 16px",
          fontSize: dims.font,
          fontWeight: 500,
          borderRadius: 6,
          border: isDark ? "1px solid #444" : "1px solid #d1d5db",
          background: isDark ? "#1f2937" : "#fff",
          color: isDark ? "#f9fafb" : "#111827",
          cursor: busy ? "wait" : "pointer",
        }}
      >
        <IALogo size={dims.logo} />
        {label}
      </button>

      {showQr && (qrUrl ?? relayUrl) && (
        <LoginQrCode
          url={qrUrl ?? relayUrl!}
          copyUrl={qrUrl ?? relayUrl ?? undefined}
          hint={
            poll.state === "awaiting_approval"
              ? "Approve the login request in Identity Agent"
              : "Open Identity Agent on your phone → Scan → point at this code"
          }
        />
      )}
    </div>
  );
}