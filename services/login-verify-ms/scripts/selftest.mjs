#!/usr/bin/env node
/** Integration self-test: golden vector library + HTTP POST /verify (T-140/T-141). */
import { spawn } from "node:child_process";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { loadGoldenVectors, runGoldenSelfTest } from "../dist/golden.js";

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
  const server = spawn("node", ["dist/server.js"], {
    cwd: MS_ROOT,
    env: { ...process.env, PORT: String(PORT), HOST: "127.0.0.1" },
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

    const passRes = await fetch(`${baseUrl}/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        assertion: g.assertion,
        expected_audience: g.expected_verify.audience,
        expected_nonce: g.expected_verify.nonce,
        signing_verkey_qb64: g.signing_verkey_qb64,
        skip_dt_check: true,
      }),
    });
    const passBody = await passRes.json();
    if (!passRes.ok || !passBody.ok) {
      fail(`golden POST /verify: ${JSON.stringify(passBody)}`);
    }
    if (passBody.i !== g.assertion.i) fail("verify i mismatch");

    const corrupt = { ...g.assertion, sig: g.negative_vectors.corrupt_sig_last_char };
    const rejectRes = await fetch(`${baseUrl}/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        assertion: corrupt,
        expected_audience: g.expected_verify.audience,
        expected_nonce: g.expected_verify.nonce,
        signing_verkey_qb64: g.signing_verkey_qb64,
        skip_dt_check: true,
      }),
    });
    const rejectBody = await rejectRes.json();
    if (rejectRes.status !== 401 || rejectBody.ok) {
      fail("corrupt sig should return 401 with ok:false");
    }

    console.log("✅ login-verify-ms selftest passed");
    console.log(`   golden said=${g.said}`);
    console.log(`   canonical_body_len=${g.canonical_body_len}`);
    console.log(`   HTTP POST /verify golden + negative vectors OK`);
  } finally {
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