// The one way the ready-built page for a utility app is made:
//
//   npm run build:app -- <output folder>
//
// writes <output folder>/identity-agent-app.js (global `IdentityAgentApp`) from
// src/bundle.tsx, with React inside, so a page loads it with a plain <script src>
// and needs no build step of its own. Every consumer runs this from the core it
// pins and keeps no copy; the file is never committed. Without a folder it writes
// to `bundle/`, which git ignores.
import { build } from "esbuild";
import { mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const outDir = resolve(process.argv[2] ?? join(root, "bundle"));
mkdirSync(outDir, { recursive: true });
await build({
  absWorkingDir: root,
  entryPoints: ["src/bundle.tsx"],
  bundle: true,
  minify: true,
  format: "iife",
  globalName: "IdentityAgentApp",
  target: "es2022",
  define: { "process.env.NODE_ENV": '"production"' },
  legalComments: "none",
  outfile: join(outDir, "identity-agent-app.js"),
});
console.log(join(outDir, "identity-agent-app.js"));
