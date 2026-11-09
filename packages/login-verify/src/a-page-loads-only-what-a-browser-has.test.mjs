// A web page loads `@identity-agent/login-verify/browser`. Nothing it imports,
// directly or through this package's own files, may need Node: no node: module,
// no express, no Buffer or process. And the check really runs with Buffer
// gone, as it is in a browser, and agrees with what Node computes.
import assert from "node:assert";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as ed from "@noble/ed25519";
import { spawnSync } from "node:child_process";

const dist = resolve(dirname(fileURLToPath(import.meta.url)), "..", "dist");
const seen = new Set();
const bare = new Set();
const walk = (file) => {
  if (seen.has(file)) return;
  seen.add(file);
  const code = readFileSync(file, "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
  assert.ok(!/\bBuffer\b|\bprocess\.|\brequire\(/.test(code), `${file} uses Buffer, process or require`);
  for (const m of code.matchAll(/(?:from|import)\s*\(?\s*["']([^"']+)["']/g)) {
    const spec = m[1];
    if (spec.startsWith(".")) walk(join(dirname(file), spec));
    else bare.add(spec);
  }
};
walk(join(dist, "browser.js"));
for (const spec of bare) {
  assert.ok(!spec.startsWith("node:") && !["fs", "crypto", "http", "express", "path"].includes(spec), `the page would load ${spec}`);
}
assert.deepEqual([...bare].sort().filter((s) => !s.startsWith("@noble/")), [], "only the noble libraries come from outside");
assert.ok(existsSync(join(dist, "browser.js")) && seen.size >= 5, "walked the real import graph");

// Run it without Buffer.
const seed = ed.utils.randomPrivateKey();
const message = new TextEncoder().encode("a canonical body");
const given = {
  pub: Array.from(await ed.getPublicKeyAsync(seed)),
  sig: Array.from(await ed.signAsync(message, seed)),
  msg: Array.from(message),
};
const script = `
  const given = ${JSON.stringify(given)};
  delete globalThis.Buffer;
  if (typeof Buffer !== "undefined") throw new Error("Buffer is still there");
  const { thumbprintP256, decodeBase64UrlStrict, matterFixedQb64, verifyEd25519, randomToken } = await import(${JSON.stringify(join(dist, "browser.js"))});
  const x = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", y = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
  const u8 = (a) => new Uint8Array(a);
  const signed = await verifyEd25519(u8(given.sig), u8(given.msg), u8(given.pub));
  const forged = await verifyEd25519(u8(given.sig), u8([...given.msg, 33]), u8(given.pub));
  const out = { signed, forged, thumb: thumbprintP256(x, y), round: Array.from(decodeBase64UrlStrict(x, 32)).length, q: matterFixedQb64("E", new Uint8Array(32).fill(7)), tok: randomToken(16).length };
  console.log(JSON.stringify(out));
`;
const ran = spawnSync(process.execPath, ["--input-type=module", "-e", script], { encoding: "utf8" });
assert.equal(ran.status, 0, ran.stderr);
const { signed, forged, thumb, round, q, tok } = JSON.parse(ran.stdout);
assert.equal(signed, true, "a genuine signature verifies with no Buffer");
assert.equal(forged, false, "an altered message does not");
const node = await import(join(dist, "browser.js"));
const x = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", y = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
assert.equal(thumb, node.thumbprintP256(x, y));
const { createHash } = await import("node:crypto");
assert.equal(thumb, createHash("sha256").update(`{"crv":"P-256","kty":"EC","x":"${x}","y":"${y}"}`).digest("base64url"), "same as node:crypto");
assert.equal(q, "E" + Buffer.from(new Uint8Array([0, ...new Uint8Array(32).fill(7)])).toString("base64url").slice(1), "same as Buffer");
assert.equal(thumb.length, 43, "an RFC 7638 thumbprint is 43 characters");
assert.equal(round, 32);
assert.equal(q, node.matterFixedQb64("E", new Uint8Array(32).fill(7)));
assert.equal(tok, 22);
console.log("the page entry needs nothing but the noble libraries, and runs with no Buffer");
