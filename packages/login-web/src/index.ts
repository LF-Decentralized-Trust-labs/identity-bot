export { SignInButton } from "./SignInButton.js";
export type { SignInButtonProps } from "./SignInButton.js";
export { LoginQrCode } from "./LoginQrCode.js";
export type { LoginQrCodeProps } from "./LoginQrCode.js";
export { detectLocalAgent, triggerLocalLogin } from "./agentDetect.js";
export { useSessionPoll } from "./useSessionPoll.js";

// G-051: imperative API for script-tag / CommonJS embed (no bundler dep)
export function createLoginButton(options: any = {}) {
  // Renders "Sign in with Identity Agent" button; on click opens modal / handshake.
  // Basic DOM impl for script use; full React via SignInButton.
  if (typeof document !== 'undefined') {
    const btn = document.createElement('button');
    btn.textContent = options.label || 'Sign in with Identity Agent';
    btn.className = 'ia-login-btn';
    // Click would trigger session + modal/QR/deep link per spec (wired in full impl).
    btn.onclick = () => {
      if (options.onClick) options.onClick();
      // For demo: alert or console; real would open LoginQrCode or triggerLocalLogin
      console.log('[login-web] createLoginButton clicked', options);
    };
    return btn;
  }
  return null;
}

export function validateInviteToken(token: string, options: any = {}) {
  const base = options.baseUrl || 'http://127.0.0.1:5050';
  return fetch(`${base}/api/invites/${encodeURIComponent(token)}`).then(r => r.json());
}

export function submitAccessRequest(assetId: string, requesterInfo: any, options: any = {}) {
  const base = options.baseUrl || 'http://127.0.0.1:5050';
  return fetch(`${base}/api/assets/${encodeURIComponent(assetId)}/requests`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(requesterInfo),
  }).then(r => r.json());
}

export function getInviteTokenFromUrl() {
  if (typeof window !== 'undefined') {
    return new URLSearchParams(window.location.search).get('invite');
  }
  return null;
}

// browser global for <script src="...">
if (typeof window !== 'undefined') {
  (window as any)['@grapeid/login-sdk'] = {
    createLoginButton,
    validateInviteToken,
    submitAccessRequest,
    getInviteTokenFromUrl,
  };
}