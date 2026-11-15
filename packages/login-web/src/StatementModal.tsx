import React from "react";
import { createRoot, type Root } from "react-dom/client";
import { LoginQrCode } from "./LoginQrCode.js";
import { statementWords, type StatementView } from "./statementWords.js";
import type { StatementPresenter } from "./app.js";

/** The screen a statement's wait is shown on (ADR-080): one modal the SDK owns, so no app draws its own.
 *  The words are `statementWords`'; this only lays them out. The statement asked is always shown, as what
 *  the page asked, so the person can compare it with their device's screen. */
export function StatementModal({ view, actions }: { view: StatementView; actions: { cancel(): void; again(): void } }) {
  const w = statementWords(view);
  const withPointer = view.state === "pointer" || view.state === "waiting" || view.state === "scanned";
  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="ia-statement-title"
      style={{ position: "fixed", inset: 0, background: "rgba(17,24,39,0.55)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 2147483000, fontFamily: "system-ui, sans-serif" }}
    >
      <div style={{ background: "#fff", color: "#111827", borderRadius: 14, padding: 24, width: "min(92vw, 440px)", maxHeight: "92vh", overflow: "auto", boxShadow: "0 10px 40px rgba(0,0,0,0.3)" }}>
        <h2 id="ia-statement-title" aria-live="polite" style={{ fontSize: 18, margin: "0 0 8px" }}>{w.title}</h2>
        <p style={{ fontSize: 14, margin: "0 0 12px", color: "#374151" }}>{w.body}</p>
        {withPointer && (
          <>
            <LoginQrCode url={view.pointer} label="Scan with your Identity Agent app" hint="Open Identity Agent → Scan → point at this code" />
            <p style={{ fontSize: 12, margin: "12px 0 4px", color: "#6b7280" }}>You are being asked to sign:</p>
            {/* Text, never markup: what the page asked, exactly as it will be signed. */}
            <pre style={{ fontSize: 12, background: "#f3f4f6", padding: 10, borderRadius: 8, whiteSpace: "pre-wrap", wordBreak: "break-word", margin: 0 }}>{view.statement}</pre>
          </>
        )}
        {w.actions.length > 0 && (
          <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 16 }}>
            {w.actions.map((a) => (
              <button key={a} type="button" onClick={() => actions[a]()} style={{ fontSize: 14, padding: "8px 14px", borderRadius: 8, border: "1px solid #d1d5db", background: a === "again" ? "#1a56db" : "#fff", color: a === "again" ? "#fff" : "#111827", cursor: "pointer" }}>
                {w.labels[a]}
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

/** The presenter `IdentityAgentApp.appSession` gives a session by default: the modal above, in a layer of
 *  its own on the page, closed when the request ends. */
export function modalPresenter(doc?: Document): StatementPresenter {
  let host: HTMLElement | null = null;
  let root: Root | null = null;
  return {
    show(view, actions) {
      if (!host) {
        const d = doc ?? document;
        host = d.createElement("div");
        d.body.appendChild(host);
        root = createRoot(host);
      }
      root!.render(<StatementModal view={view} actions={actions} />);
    },
    close() {
      root?.unmount();
      host?.remove();
      root = null;
      host = null;
    },
  };
}

/** Draws one state of the wait into `el`, for the preview page (previews/statement-states.html). */
export function previewStatementState(el: HTMLElement, view: StatementView): void {
  createRoot(el).render(<StatementModal view={view} actions={{ cancel() {}, again() {} }} />);
}
