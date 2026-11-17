// Runs every test in src/ (each file named *.test.mjs), one node process per
// file, in name order, and fails if any fails or if there are none. A new test
// is run by being there; there is no list of tests to add it to.
import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const tests = readdirSync(join(root, "src")).filter((f) => f.endsWith(".test.mjs")).sort();
if (tests.length === 0) {
  console.error("no tests found in src/");
  process.exit(1);
}
const failed = [];
for (const t of tests) {
  const r = spawnSync(process.execPath, [join("src", t)], { cwd: root, stdio: "inherit" });
  if (r.status !== 0) failed.push(t);
}
console.log(`${tests.length - failed.length} of ${tests.length} test files passed`);
if (failed.length) {
  console.error("failed:\n  " + failed.join("\n  "));
  process.exit(1);
}
