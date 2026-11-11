// `npm run build:app` is the one way the ready-built page is made, and what it
// writes is what a page loads: a script that, run in a bare page with no React
// of its own, defines IdentityAgentApp with everything a page calls.
import assert from "node:assert";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const root = fileURLToPath(new URL("..", import.meta.url));
const dir = mkdtempSync(join(tmpdir(), "built-page-"));
try {
  execFileSync(process.execPath, [join(root, "scripts/build-app.mjs"), dir], { cwd: root, stdio: "pipe" });
  const code = readFileSync(join(dir, "identity-agent-app.js"), "utf8");
  // The names a browser page has and a bare V8 context does not.
  const page = { document: {}, location: { hash: "" }, navigator: {}, console, TextEncoder, TextDecoder, URL, URLSearchParams, crypto: globalThis.crypto, atob, btoa, setTimeout, clearTimeout, fetch, AbortController, sessionStorage: { getItem: () => null, setItem() {} } };
  page.window = page;
  vm.runInNewContext(code + "\n;globalThis.__app = IdentityAgentApp;", page);
  const app = page.__app;
  for (const name of ["appSession", "mountSignIn", "readAppLink", "signInProblem"]) {
    assert.strictEqual(typeof app[name], "function", `the built page lacks ${name}`);
  }
  assert.strictEqual(typeof app.SessionEnded, "function", "the built page lacks SessionEnded");
} finally {
  rmSync(dir, { recursive: true, force: true });
}
console.log("the built page exports what pages use");
