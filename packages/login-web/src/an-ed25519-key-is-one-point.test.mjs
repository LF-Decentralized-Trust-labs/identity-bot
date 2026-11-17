// Every case in test-vectors/ed25519-keys.json holds in TypeScript: a key that names no single signer
// (not a point, not canonical, of small order) is refused as a witness key (B) and as a verification key (D).
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { decodeMatterRaw } from "@identity-agent/login-verify/browser";

const v = JSON.parse(readFileSync(new URL("../test-vectors/ed25519-keys.json", import.meta.url), "utf8"));
assert.ok(v.cases.length >= 10);
for (const c of v.cases) {
  for (const [code, q] of [["B", c.b], ["D", c.d]]) {
    const got = decodeMatterRaw(q, code, 32);
    assert.equal(got !== null, c.ok, `${c.name} as code ${code}`);
    if (c.ok) assert.equal(Buffer.from(got).toString("hex"), c.raw_hex, c.name);
  }
}
console.log("ed25519 keys: every case in test-vectors/ed25519-keys.json holds in TypeScript");
