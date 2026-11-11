// `bundle/identity-agent-app.js` is built from the sources, not kept by hand:
// building it again gives the same bytes, and it holds what a page uses.
import assert from "node:assert";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const dir = mkdtempSync(join(tmpdir(), "bundle-"));
try {
  const out = join(dir, "identity-agent-app.js");
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const args = pkg.scripts.bundle.split(/\s+/).slice(1).map((a) => a.replace(/^'|'$/g, "").replace("--outfile=bundle/identity-agent-app.js", "--outfile=" + out));
  const fixed = args.map((a) => (a.startsWith("--define:") ? '--define:process.env.NODE_ENV="production"' : a));
  execFileSync(join(root, "node_modules/.bin/esbuild"), fixed, { cwd: root, stdio: "pipe" });
  const built = readFileSync(out, "utf8");
  const committed = readFileSync(join(root, "bundle/identity-agent-app.js"), "utf8");
  assert.ok(built === committed, "bundle/identity-agent-app.js is not what the sources build: run npm run bundle");
  for (const name of ["IdentityAgentApp", "appSession", "mountSignIn", "readAppLink", "signOut"]) assert.ok(committed.includes(name), `the bundle lacks ${name}`);
} finally {
  rmSync(dir, { recursive: true, force: true });
}
console.log("the bundle is what the sources build");
