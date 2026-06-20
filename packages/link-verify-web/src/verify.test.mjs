import assert from "node:assert/strict";
import { outcomeLabel } from "../dist/badge.js";

assert.equal(outcomeLabel("verified"), "Verified");
assert.equal(outcomeLabel("tampered"), "Tampered");
assert.equal(outcomeLabel("unverified"), "Unverified");
assert.equal(outcomeLabel("incomplete"), "Incomplete");
console.log("link-verify-web: verify.test.mjs OK");