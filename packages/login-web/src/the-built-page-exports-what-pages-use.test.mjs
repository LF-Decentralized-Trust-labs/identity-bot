// `npm run build:app` is the one way the ready-built page is made, and what it
// writes is what a page loads: a script that, run in a bare page with no React
// of its own, defines IdentityAgentApp with everything a page calls. What a page
// calls is what the entry, src/bundle.tsx, exports: the names are read from it
// with the TypeScript compiler, so an export added there is checked here
// without being listed twice.
import assert from "node:assert";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import ts from "typescript";

const root = fileURLToPath(new URL("..", import.meta.url));

// The values src/bundle.tsx exports (types and interfaces leave nothing in the
// built page), and whether each is a function or a class.
function entryExports() {
  const entry = join(root, "src/bundle.tsx");
  const program = ts.createProgram([entry], { jsx: ts.JsxEmit.ReactJSX, module: ts.ModuleKind.NodeNext, moduleResolution: ts.ModuleResolutionKind.NodeNext, target: ts.ScriptTarget.ES2022, noEmit: true, skipLibCheck: true });
  const checker = program.getTypeChecker();
  const module = checker.getSymbolAtLocation(program.getSourceFile(entry));
  const out = new Map();
  for (const sym of checker.getExportsOfModule(module)) {
    const target = sym.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(sym) : sym;
    if (!(target.flags & ts.SymbolFlags.Value)) continue;
    const decl = target.valueDeclaration;
    const callable = target.flags & (ts.SymbolFlags.Function | ts.SymbolFlags.Class)
      || (decl && checker.getTypeOfSymbolAtLocation(target, decl).getCallSignatures().length > 0);
    out.set(sym.getName(), Boolean(callable));
  }
  return out;
}
const exported = entryExports();
// A reading that found nothing, or missed the one call every page makes, would pass vacuously.
assert.ok(exported.get("mountSignIn"), "could not read the exports of src/bundle.tsx");
const dir = mkdtempSync(join(tmpdir(), "built-page-"));
try {
  execFileSync(process.execPath, [join(root, "scripts/build-app.mjs"), dir], { cwd: root, stdio: "pipe" });
  const code = readFileSync(join(dir, "identity-agent-app.js"), "utf8");
  // The names a browser page has and a bare V8 context does not.
  const page = { document: {}, location: { hash: "" }, navigator: {}, console, TextEncoder, TextDecoder, URL, URLSearchParams, crypto: globalThis.crypto, atob, btoa, setTimeout, clearTimeout, fetch, AbortController, sessionStorage: { getItem: () => null, setItem() {} } };
  page.window = page;
  vm.runInNewContext(code + "\n;globalThis.__app = IdentityAgentApp;", page);
  const app = page.__app;
  for (const [name, callable] of exported) {
    if (callable) assert.strictEqual(typeof app[name], "function", `the built page lacks ${name}`);
    else assert.notStrictEqual(app[name], undefined, `the built page lacks ${name}`);
  }
  // Nothing the built page carries is missing from what the entry declares.
  assert.deepStrictEqual(Object.keys(app).sort(), [...exported.keys()].sort());
  // The built page has no unpinned read of a link: one with no pin is refused before it is read.
  assert.throws(() => app.readAppLink("#aid=x"), /not set up to sign anybody in/);
  assert.strictEqual(app.readAppLink, app.readPinnedAppLink);
  // The session a page opens offers signStatement, with the SDK's own screen for the wait.
  assert.strictEqual(typeof app.appSession.length, "number");
  assert.match(app.statementWords({ state: "waiting", pointer: "p", statement: "s" }).body, /Nothing is signed until you approve on it/);
} finally {
  rmSync(dir, { recursive: true, force: true });
}
console.log("the built page exports what pages use");
