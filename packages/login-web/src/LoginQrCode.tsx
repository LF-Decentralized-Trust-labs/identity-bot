import React, { useEffect, useState } from "react";
import QRCode from "qrcode";

export interface LoginQrCodeProps {
  /** Minimal payload encoded in the QR (low density). */
  url: string;
  /** Full link for copy/paste; defaults to url when omitted. */
  copyUrl?: string;
  size?: number;
  label?: string;
  hint?: string;
  showCopyLink?: boolean;
}

export function LoginQrCode({
  url,
  copyUrl,
  size = 200,
  label = "Scan with your Identity Agent app",
  hint = "Open Identity Agent → Scan → point at this code",
  showCopyLink = true,
}: LoginQrCodeProps) {
  const linkToCopy = copyUrl ?? url;
  const [dataUrl, setDataUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setError(null);
    setDataUrl(null);

    // Match Identity Agent core (qr_flutter): auto version, low error correction.
    QRCode.toDataURL(url, {
      width: size,
      margin: 1,
      errorCorrectionLevel: "L",
      color: { dark: "#111827", light: "#ffffff" },
    })
      .then((result) => {
        if (!cancelled) setDataUrl(result);
      })
      .catch((err: Error) => {
        if (!cancelled) setError(err.message);
      });

    return () => {
      cancelled = true;
    };
  }, [url, size]);

  const copyLink = async () => {
    try {
      await navigator.clipboard.writeText(linkToCopy);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div style={{ marginTop: 16, textAlign: "center" }}>
      <p style={{ fontSize: 14, marginBottom: 12, fontWeight: 500 }}>{label}</p>

      <div
        style={{
          display: "inline-block",
          padding: 12,
          background: "#fff",
          border: "1px solid #e5e7eb",
          borderRadius: 12,
          boxShadow: "0 1px 3px rgba(0,0,0,0.08)",
        }}
      >
        {dataUrl ? (
          <img
            src={dataUrl}
            alt="QR code to sign in with Identity Agent"
            width={size}
            height={size}
            style={{ display: "block" }}
          />
        ) : error ? (
          <div
            style={{
              width: size,
              height: size,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontSize: 12,
              color: "#b91c1c",
              padding: 16,
            }}
          >
            QR failed: {error}
          </div>
        ) : (
          <div
            style={{
              width: size,
              height: size,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontSize: 13,
              color: "#6b7280",
            }}
          >
            Generating QR…
          </div>
        )}
      </div>

      <p style={{ fontSize: 12, color: "#6b7280", marginTop: 10, maxWidth: 280, marginInline: "auto" }}>
        {hint}
      </p>

      {showCopyLink && (
        <button
          type="button"
          onClick={copyLink}
          style={{
            marginTop: 8,
            fontSize: 12,
            color: "#4b5563",
            background: "transparent",
            border: "none",
            cursor: "pointer",
            textDecoration: "underline",
          }}
        >
          {copied ? "Link copied" : "Copy link instead"}
        </button>
      )}
    </div>
  );
}