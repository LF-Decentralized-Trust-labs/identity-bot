#!/usr/bin/env node
/**
 * Local login E2E: minimal RP (dev relay + login-verify) + IA core login API.
 * Run with IA core on :5050 (ENABLE_KERI_DRIVER=false is fine).
 *
 *   ENABLE_KERI_DRIVER=false go run .   # in identity-agent-core
 *   node src/local-login-e2e.mjs        # in packages/login-verify
 */

import express from "express";
import { createServer } from "node:http";
import {
  IdentityAgentVerifier,
  generateDevSiteIdentity,
  createDevRelayServer,
  mountIdentityAgentLoginRoutes,
} from "../dist/index.js";

const IA_BASE = process.env.IA_BASE ?? "http://127.0.0.1:5050";
const RP_PORT = parseInt(process.env.RP_PORT ?? "5000", 10);
const RP_BASE = `http://127.0.0.1:${RP_PORT}`;

async function waitFor(url, label, attempts = 30) {
  for (let i = 0; i < attempts; i++) {
    try {
      const r = await fetch(url);
      if (r.ok) return;
    } catch {
      // retry
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`${label} not ready at ${url}`);
}

async function startRp() {
  const relay = createDevRelayServer({ port: 0, host: "127.0.0.1" });
  const { url: relayUrl, server: relayServer } = await relay.start();
  const site = await generateDevSiteIdentity(relayUrl);
  relay.registerIdentity(site);

  const verifier = new IdentityAgentVerifier({
    siteIdentity: site,
    devRelayBaseUrl: relayUrl,
  });

  const app = express();
  app.use(express.json());
  mountIdentityAgentLoginRoutes(app, verifier, {
    sessionPath: "/auth/ia/session",
    issueAppSession: (aid) => `tok-${aid.slice(0, 12)}`,
  });

  const server = createServer(app);
  await new Promise((resolve) => server.listen(RP_PORT, "127.0.0.1", resolve));

  return { relayUrl, relayServer, server, site };
}

async function main() {
  console.log("=== Local login E2E ===");
  console.log(`IA core: ${IA_BASE}`);
  console.log(`RP stub: ${RP_BASE}`);

  await waitFor(`${IA_BASE}/api/health`, "IA core");

  const rp = await startRp();
  console.log(`Dev relay: ${rp.relayUrl}`);
  console.log(`Site AID: ${rp.site.aid}`);

  const sessionResp = await fetch(`${RP_BASE}/auth/ia/session`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ requestDisclosures: ["display_name", "email"] }),
  });
  if (!sessionResp.ok) {
    throw new Error(`session create failed: ${sessionResp.status} ${await sessionResp.text()}`);
  }
  const session = await sessionResp.json();
  console.log("1. RP session created:", session.session_token?.slice(0, 16) + "...");

  const previewResp = await fetch(`${IA_BASE}/api/login/preview`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      session_token: session.session_token,
      rp_session_url: RP_BASE,
    }),
  });
  if (!previewResp.ok) {
    throw new Error(`login preview failed: ${previewResp.status} ${await previewResp.text()}`);
  }
  const preview = await previewResp.json();
  console.log("2. IA preview OK — site:", preview.site_aid?.slice(0, 16) + "...");
  console.log("   Disclosures:", preview.disclosure_preview);

  const approveResp = await fetch(`${IA_BASE}/api/login/approve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      session_token: session.session_token,
      rp_session_url: RP_BASE,
    }),
  });
  if (!approveResp.ok) {
    throw new Error(`login approve failed: ${approveResp.status} ${await approveResp.text()}`);
  }
  const approved = await approveResp.json();
  console.log("3. IA approve OK — pairwise:", approved.pairwise_aid?.slice(0, 16) + "...");

  const stateResp = await fetch(`${RP_BASE}/auth/ia/session/${session.session_token}`);
  if (!stateResp.ok) {
    throw new Error(`session poll failed: ${stateResp.status}`);
  }
  const state = await stateResp.json();
  if (state.state !== "verified") {
    throw new Error(`expected verified, got ${state.state}`);
  }
  console.log("4. RP session verified ✓");
  console.log("\nPASS — local login E2E complete");

  await new Promise((resolve, reject) => rp.server.close((err) => (err ? reject(err) : resolve())));
  await new Promise((resolve, reject) => rp.relayServer.close((err) => (err ? reject(err) : resolve())));
}

main().catch((e) => {
  console.error("\nFAIL —", e.message);
  process.exit(1);
});