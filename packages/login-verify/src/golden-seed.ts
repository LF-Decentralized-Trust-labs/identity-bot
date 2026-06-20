/** Deterministic Ed25519 seed for the login golden vector. */
export const M29_GOLDEN_SIGNING_SEED = new Uint8Array([
  0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
  0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
  0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
  0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
]);

export const M29_GOLDEN_ASSERTION_INPUT = {
  v: "IALOGIN10JSON" as const,
  t: "login-assertion" as const,
  i: "Em29GoldenPairwiseAID0123456789ABCDEFGHIJK",
  relationship_aid_oobi:
    "https://k7f2p.relay.grapeid.org/oobi/Em29GoldenPairwiseAID0123456789ABCDEFGHIJK",
  audience: "https://app.example.com",
  nonce: "m29GoldenNonce0123456789ABCDEFGH",
  dt: "2026-06-17T12:00:00Z",
  disclosures: { display_name: "Alice", email: "alice@example.com" },
  presented_acdcs: [] as unknown[],
};

export const M29_GOLDEN_CHALLENGE_EXPECTED = {
  audience: "https://app.example.com",
  nonce: "m29GoldenNonce0123456789ABCDEFGH",
};