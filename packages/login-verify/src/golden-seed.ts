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
  // A real identity: the inception of the golden key (seed 0x29..0x48, next
  // key from seed 0x49..0x68), whose signed key log is p_kel below. The Go
  // side checks that the log derives i and puts the golden key in force.
  i: "EIQ1ViYdMzEwjQFL0L6iwx32TOOJpqtAgFndcOwny4jN",
  relationship_aid_oobi:
    "https://k7f2p.relay.grapeid.org/oobi/EIQ1ViYdMzEwjQFL0L6iwx32TOOJpqtAgFndcOwny4jN",
  audience: "https://app.example.com",
  nonce: "m29GoldenNonce0123456789ABCDEFGH",
  dt: "2026-06-17T12:00:00Z",
  disclosures: { display_name: "Alice", email: "alice@example.com" },
  presented_acdcs: [] as unknown[],
  p_kel:
    "eyJyYXdfZXZlbnRzX2I2NCI6WyJleUoySWpvaVMwVlNTVEV3U2xOUFRqQXdNREV5WWw4aUxDSjBJam9pYVdOd0lpd2laQ0k2SWtWSlVURldhVmxrVFhwRmQycFJSa3d3VERacGQzZ3pNbFJQVDBwd2NYUkJaMFp1WkdOUGQyNTVOR3BPSWl3aWFTSTZJa1ZKVVRGV2FWbGtUWHBGZDJwUlJrd3dURFpwZDNnek1sUlBUMHB3Y1hSQlowWnVaR05QZDI1NU5HcE9JaXdpY3lJNklqQWlMQ0pyZENJNklqRWlMQ0pySWpwYklrUk5aWEZUYlhwck9XVmhSVXQ2TTNOdFgyVmtUVmx0TW1kRlozRlJhVEprY1VSWUxXMWZMVzFtZVRkNElsMHNJbTUwSWpvaU1TSXNJbTRpT2xzaVJVNHhSRTVKVTJrMmQxcE9RbHBIZFcxTk5uWlZWWEZUY0ZCbllqVXRaV2Q1YkdkcVMwMUViSGhXVERraVhTd2lZblFpT2lJd0lpd2lZaUk2VzEwc0ltTWlPbHRkTENKaElqcGJYWDA9Il0sImNlc3Jfc2lnbmF0dXJlcyI6WyIwQkNEczduZ0VyVEJGX2RfV3JLZ1Y4UlBIVXpMcmF2Y3hzb0hNempVMkw0QjF2ekhKR1E0RkxaOE1rQkhQYnFBVXNzZG5hdGk4VlcwUjE2Y0dPLTd3Z2tKIl19",
  site_aid: "EM29GoldenSiteAID0123456789ABCDEFGHIJKLMNOPQ",
};

export const M29_GOLDEN_CHALLENGE_EXPECTED = {
  audience: "https://app.example.com",
  nonce: "m29GoldenNonce0123456789ABCDEFGH",
  site_aid: "EM29GoldenSiteAID0123456789ABCDEFGHIJKLMNOPQ",
};