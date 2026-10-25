#!/usr/bin/env node
/** Integration self-test: golden vector library + HTTP POST /verify. */
import { spawn } from "node:child_process";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import * as crypto from "node:crypto";
import { assertionDigest, canonicalAssertionBody, signCanonical } from "@identity-agent/login-verify";
import { loadGoldenVectors, runGoldenSelfTest } from "../dist/golden.js";

// The stand-in organisation Identity Agent is the package's own, so the two
// test suites check the same wire and cannot drift apart.
import { anIdentityAgentStandIn } from "../../../packages/login-verify/src/an-identity-agent-stand-in.mjs";

async function aFreshAssertion(ia) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const seed = new Uint8Array(Buffer.from(privateKey.export({ format: "jwk" }).d, "base64url"));
  const pub = publicKey.export({ format: "jwk" }).x;
  const aid = "EAFreshPairwiseIdentity0000000000000000000000";
  const assertion = {
    v: "IALOGIN10JSON", t: "login-assertion", i: aid,
    relationship_aid_oobi: "https://site.example/oobi/" + aid,
    audience: "https://site.example", nonce: "n-" + Date.now(),
    dt: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    disclosures: {}, presented_acdcs: [], p_kel: "its-signed-key-log", site_aid: "EThisSite",
  };
  ia.knows(aid, assertion.p_kel, Buffer.from(pub, "base64url"));
  assertion.d = assertionDigest(assertion);
  assertion.sig = await signCanonical(canonicalAssertionBody(assertion), seed);
  return { assertion };
}

const MS_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PORT = 18091 + Math.floor(Math.random() * 1000);

function fail(msg) {
  console.error(`selftest failed: ${msg}`);
  process.exit(1);
}

async function waitForHealth(baseUrl, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${baseUrl}/health`);
      if (res.ok) {
        const body = await res.json();
        if (body.golden_vector_ok) return body;
      }
    } catch {
      // server still starting
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  fail("server did not become healthy");
}

async function main() {
  const golden = await runGoldenSelfTest();
  if (!golden.ok) fail(golden.reason);

  const g = loadGoldenVectors().login_assertion;
  const ia = await anIdentityAgentStandIn();
  const server = spawn("node", ["dist/server.js"], {
    cwd: MS_ROOT,
    env: { ...process.env, PORT: String(PORT), HOST: "127.0.0.1", IDENTITY_AGENT_URL: ia.url },
    stdio: ["ignore", "pipe", "pipe"],
  });

  let serverLog = "";
  server.stdout.on("data", (d) => {
    serverLog += d;
  });
  server.stderr.on("data", (d) => {
    serverLog += d;
  });

  const baseUrl = `http://127.0.0.1:${PORT}`;
  try {
    const health = await waitForHealth(baseUrl);
    if (health.status !== "active") fail(`health status=${health.status}`);

    // A key the caller supplies is refused: the key comes from the
    // assertion's key log, checked by the organisation's Identity Agent.
    const callerKeyRes = await fetch(`${baseUrl}/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        assertion: g.assertion,
        expected_audience: g.expected_verify.audience,
        expected_nonce: g.expected_verify.nonce,
        expected_site_aid: "ESite",
        signing_verkey_qb64: g.signing_verkey_qb64,
      }),
    });
    if (callerKeyRes.status !== 400) fail(`a caller-supplied key was not refused (${callerKeyRes.status})`);

    // A fresh assertion, its key established by the stand-in Identity Agent.
    const fresh = await aFreshAssertion(ia);
    const passRes = await fetch(`${baseUrl}/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        assertion: fresh.assertion,
        expected_audience: fresh.assertion.audience,
        expected_nonce: fresh.assertion.nonce,
        expected_site_aid: fresh.assertion.site_aid,
      }),
    });
    const passBody = await passRes.json();
    if (!passRes.ok || !passBody.ok) fail(`POST /verify: ${JSON.stringify(passBody)}`);
    if (passBody.i !== fresh.assertion.i) fail("verify i mismatch");

    const otherSiteRes = await fetch(`${baseUrl}/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        assertion: fresh.assertion,
        expected_audience: fresh.assertion.audience,
        expected_nonce: fresh.assertion.nonce,
        expected_site_aid: "ESomeOtherSite",
      }),
    });
    if (otherSiteRes.status !== 401) fail("an assertion for another site was accepted");

    console.log("✅ login-verify-ms selftest passed");
    console.log(`   golden said=${g.said}`);
    console.log(`   canonical_body_len=${g.canonical_body_len}`);
    console.log(`   HTTP POST /verify: key from the key log, caller's key and another site refused`);
  } finally {
    await ia.close();
    server.kill("SIGTERM");
    await new Promise((r) => server.on("exit", r));
    if (server.exitCode && server.exitCode !== 0 && !server.signalCode) {
      console.error(serverLog);
      fail(`server exited ${server.exitCode}`);
    }
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});