import type { Outcome, VerificationResult } from "./types.js";

export interface BadgeRenderOptions {
  showOwnership?: boolean;
  className?: string;
}

const OUTCOME_LABEL: Record<Outcome, string> = {
  verified: "Verified",
  tampered: "Tampered",
  unverified: "Unverified",
  incomplete: "Incomplete",
};

const BAND_COLOR: Record<string, string> = {
  green: "#16a34a",
  red: "#dc2626",
  amber: "#d97706",
  gray: "#6b7280",
};

/**
 * Minimal DOM badge renderer (SCR1). Keys off `outcome` per SEAM-15 §2.3.
 */
export function renderBadge(
  container: HTMLElement,
  result: VerificationResult,
  options: BadgeRenderOptions = {}
): void {
  const color = BAND_COLOR[result.band ?? "gray"] ?? BAND_COLOR.gray;
  const label = OUTCOME_LABEL[result.outcome] ?? result.outcome;
  container.innerHTML = "";
  container.className = options.className ?? "ia-link-verify-badge";
  container.style.cssText = [
    "display:inline-flex",
    "align-items:center",
    "gap:6px",
    "font:500 12px/1.2 system-ui,sans-serif",
    `color:${color}`,
  ].join(";");

  const dot = document.createElement("span");
  dot.setAttribute("aria-hidden", "true");
  dot.style.cssText = `width:8px;height:8px;border-radius:50%;background:${color}`;
  container.appendChild(dot);

  const text = document.createElement("span");
  text.textContent = label;
  container.appendChild(text);

  if (
    options.showOwnership &&
    result.ownership?.registered_to &&
    result.outcome === "verified"
  ) {
    const own = document.createElement("span");
    own.style.color = "#374151";
    own.textContent = ` · ${result.ownership.registered_to}`;
    container.appendChild(own);
  }
}

export function outcomeLabel(outcome: Outcome): string {
  return OUTCOME_LABEL[outcome] ?? outcome;
}