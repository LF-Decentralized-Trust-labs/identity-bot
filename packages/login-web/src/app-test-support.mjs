// What the tests of a utility app's page share: an identity with a one-event
// key log, made the way a core makes one.
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { blake3Qb64, ed25519SigQb64, ed25519VerkeyQb64 } from "../../login-verify/dist/browser.js";

export const enc = new TextEncoder();
export const b64u = (b) => Buffer.from(b).toString("base64url");

export function identity() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url");
  const key = ed25519VerkeyQb64(new Uint8Array(pub));
  const blank = "#".repeat(44);
  const ev = (d) => `{"v":"KERI10JSON000000_","t":"icp","d":"${d}","i":"${d}","s":"0","kt":"1","k":["${key}"],"nt":"1","n":[],"bt":"0","b":[],"c":[],"a":[]}`;
  const aid = blake3Qb64(enc.encode(ev(blank)));
  const text = ev(aid);
  const sign = (bytes) => edSign(null, Buffer.from(bytes), privateKey);
  const log = (over = {}) => b64u(JSON.stringify({ raw_events_b64: [Buffer.from(text).toString("base64")], cesr_signatures: [ed25519SigQb64(new Uint8Array(sign(enc.encode(text))))], ...over }));
  return { aid, key: new Uint8Array(pub), text, sign, log };
}
