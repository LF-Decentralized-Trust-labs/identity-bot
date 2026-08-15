// Confirming a session must carry the collector secret, and must not quietly
// report success when the Identity Agent withholds the identity.
import assert from "node:assert";
import { confirmLoginSession } from "../dist/confirmSession.js";

async function run() {
  // The secret reaches the Identity Agent as a header, never in the URL, so it
  // cannot end up in a log, a referrer or a QR code.
  let seenHeader = null;
  let seenUrl = null;
  const verified = await confirmLoginSession({
    agentUrl: "https://ia.example",
    assetId: "the-portal",
    sessionToken: "tok",
    collectorSecret: "s3cret",
    fetchFn: async (url, init) => {
      seenUrl = String(url);
      seenHeader = init.headers["X-Collector-Secret"];
      return {
        ok: true,
        json: async () => ({
          state: "verified",
          app_session_token: "EPairwise",
          member_info: { role: "Editor", display_name: "Alice" },
        }),
      };
    },
  });
  assert.equal(seenHeader, "s3cret", "the collector secret was not sent");
  assert.ok(!seenUrl.includes("s3cret"), "the secret leaked into the URL");
  assert.equal(verified.state, "verified");
  assert.equal(verified.pairwiseAid, "EPairwise");
  assert.equal(verified.memberInfo.displayName, "Alice");

  // Verified-but-withheld is the shape a caller gets when it has lost or never
  // had the secret. Reporting it as pending would spin forever; reporting it as
  // verified would sign somebody in as nobody.
  await assert.rejects(
    () =>
      confirmLoginSession({
        agentUrl: "https://ia.example",
        assetId: "the-portal",
        sessionToken: "tok",
        fetchFn: async () => ({
          ok: true,
          json: async () => ({ state: "verified", identity_withheld: true }),
        }),
      }),
    /collectorSecret/,
    "a withheld identity was not reported",
  );

  // A refusal still comes back as a refusal.
  const declined = await confirmLoginSession({
    agentUrl: "https://ia.example",
    assetId: "the-portal",
    sessionToken: "tok",
    collectorSecret: "s3cret",
    fetchFn: async () => ({
      ok: true,
      json: async () => ({ state: "declined", reason: "not an active employee" }),
    }),
  });
  assert.equal(declined.state, "declined");
  assert.equal(declined.reason, "not an active employee");

  console.log("confirm session: the secret travels as a header, and a withheld identity is not a silent success");
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
