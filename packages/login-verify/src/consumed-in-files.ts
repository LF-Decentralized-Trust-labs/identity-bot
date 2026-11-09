import { createHash } from "node:crypto";
import { mkdirSync, openSync, closeSync, writeSync, readdirSync, readFileSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import type { ConsumedNonces } from "./standalone-verify.js";

/** A replay store kept as files in one directory: it survives a restart, and
 *  every process and instance that points at the same directory (a shared
 *  volume) shares it.
 *
 *  A claim is a file created with `O_EXCL`, so of two processes claiming the
 *  same assertion at once the filesystem lets exactly one win; no lock is
 *  needed. The file name is a hash of the key and its content is the time the
 *  entry may be forgotten, so a sweep needs nothing else. A claim made without
 *  a keep-until time is never swept.
 *
 *  A directory that cannot be written makes `claim` throw, and the verifier
 *  refuses the sign-in: an assertion that cannot be recorded is not accepted.
 *  For a deployment that has Redis instead, `claim` is `SET key 1 NX PXAT
 *  keepUntilMs` and `release` is `DEL`: the same two methods.
 *
 *  This module imports `node:fs`, which is why it is not in the package's main
 *  entry; import it from `@identity-agent/login-verify/consumed-in-files`. */
export function fileConsumedNonces(dir: string, opts: { sweepEveryMs?: number } = {}): ConsumedNonces {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const sweepEvery = opts.sweepEveryMs ?? 60_000;
  let sweptAt = 0;
  const path = (key: string) => join(dir, createHash("sha256").update(key).digest("hex") + ".claim");

  const sweep = (now: number) => {
    for (const name of readdirSync(dir)) {
      if (!name.endsWith(".claim")) continue;
      const file = join(dir, name);
      try {
        const text = readFileSync(file, "utf8");
        // An empty file is a claim another process is part-way through writing.
        if (text === "") continue;
        const until = Number(text);
        if (Number.isFinite(until) && until <= now) unlinkSync(file);
      } catch {
        // Gone already, or being written: leave it for the next sweep.
      }
    }
  };

  return {
    claim(key: string, keepUntilMs?: number) {
      const now = Date.now();
      if (now - sweptAt >= sweepEvery) {
        sweptAt = now;
        sweep(now);
      }
      const file = path(key);
      let fd: number;
      try {
        fd = openSync(file, "wx", 0o600);
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "EEXIST") return false;
        throw err;
      }
      try {
        writeSync(fd, String(keepUntilMs ?? "never"));
      } finally {
        closeSync(fd);
      }
      return true;
    },
    release(key: string) {
      try {
        unlinkSync(path(key));
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
      }
    },
  };
}
