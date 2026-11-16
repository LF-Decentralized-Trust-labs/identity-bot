// The page applies the rule for a utility app's back-end address that the Identity Agent core applies
// (identity-agent-core/backendaddr): every case in login-verify's back-end-addresses.json is decided
// alike. A page has no build mode, so it accepts http on this machine, which the core accepts only in a
// development build.
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { backEndAddress, readLinkBackEnd, readAppLink } from "../dist/app.js";

const v = JSON.parse(readFileSync(new URL("../../login-verify/test-vectors/back-end-addresses.json", import.meta.url), "utf8"));
assert.ok(v.addresses.length >= 40 && v.links.length >= 8, "the shared vectors are missing cases");

for (const c of v.addresses) {
  assert.equal(backEndAddress(c.address), c.accepted, `${c.name} (${JSON.stringify(c.address)}): the page says ${!c.accepted}, the file says ${c.accepted}`);
}
for (const c of v.links) {
  assert.equal(readLinkBackEnd(c.link_api), c.read_as, `${c.name} (${JSON.stringify(c.link_api)})`);
}
assert.equal(backEndAddress("https://tasks.example.com/" + "a".repeat(2048)), false, "an address over the bound was accepted");

// A link whose api is refused by the rule is refused when it is read, and one the rule accepts is read.
const complete = JSON.parse(readFileSync(new URL("../test-vectors/app-checks.json", import.meta.url), "utf8")).links.find((l) => l.name === "a complete link");
const withApi = (api) => {
  const p = new URLSearchParams(complete.hash.replace(/^#/, ""));
  p.set("api", api);
  return "#" + p.toString();
};
for (const api of ["https://169.254.169.254", "https://10.0.0.5/", "http://tasks.example.com", "https://intranet"]) {
  let err;
  try { readAppLink(withApi(api), complete.now_ms); } catch (e) { err = e; }
  assert.ok(err && err.message.includes("no back end"), `a link naming ${api} was read: ${err ? err.message : "no refusal"}`);
}
assert.equal(readAppLink(withApi("https://tasks.example.com/"), complete.now_ms).api, "https://tasks.example.com");

console.log(`back-end address: ${v.addresses.length} addresses and ${v.links.length} links decided as the core decides them`);
