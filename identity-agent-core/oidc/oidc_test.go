package oidc

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"identity-agent-core/login"
)

func TestDiscoveryConformance(t *testing.T) {
	doc := BuildDiscovery("http://127.0.0.1:8765/Eabc123")
	res := ValidateDiscovery(doc)
	if !res.OK {
		t.Fatalf("conformance failed: %v", res.Errors)
	}
	if res.Profile != EUDIARFProfileVersion {
		t.Fatalf("profile = %s", res.Profile)
	}
}

func TestClaimsMappingAndIDTokenWrapsAssertion(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 0x29)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	aid := "E" + base64.RawURLEncoding.EncodeToString(pub)[:43]

	bundle := login.ChallengeBundle{
		V: "ASK1", T: 1,
		SiteAID: "Esite", Audience: "https://rp.example", Nonce: "nonce-1",
		RequestedDisclosures: []string{"display_name", "email"},
	}
	rel := login.SiteRelationship{
		SiteAID: "Esite", PairwiseAID: aid, SeedB64: base64.StdEncoding.EncodeToString(seed),
		DisplayName: "Alice", Email: "alice@example.com",
	}
	h, err := login.NewHandler(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := h.BuildAssertion(&rel, &bundle, nil)
	if err != nil {
		t.Fatal(err)
	}
	idToken, err := BuildIDToken("127.0.0.1:8765", assertion, seed, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		t.Fatalf("expected JWT, got %d parts", len(parts))
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["iss"] != "did:webs:127.0.0.1:8765:"+aid {
		t.Fatalf("iss = %v", claims["iss"])
	}
	if claims["sub"] != claims["iss"] {
		t.Fatal("sub must equal iss for SIOPv2")
	}
	if claims["name"] != "Alice" || claims["email"] != "alice@example.com" {
		t.Fatalf("disclosure claims: %v", claims)
	}
	if claims[ClaimSeam8AssertionDigest] != assertion.D {
		t.Fatal("missing seam8_assertion_digest")
	}
	embedded, ok := claims[ClaimSeam8Assertion].(map[string]interface{})
	if !ok || embedded["sig"] == nil {
		t.Fatal("embedded seam8_assertion must include sig")
	}
}

func TestVPFormatsNegotiation(t *testing.T) {
	assertion := &login.Assertion{
		I: "Eabc", D: "Esaid", Dt: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		CustomData: map[string]interface{}{
			"score_attestation": map[string]interface{}{"band": "green", "score": 75},
		},
	}
	sdjwt, err := BuildVPToken(VPFormatSDJWT, assertion)
	if err != nil || sdjwt.Format != VPFormatSDJWT {
		t.Fatalf("sdjwt: %v %v", sdjwt, err)
	}
	acdc, err := BuildVPToken(VPFormatACDC, assertion)
	if err != nil || acdc.Format != VPFormatACDC {
		t.Fatalf("acdc: %v %v", acdc, err)
	}
}

func TestParseAuthRequestMapsToSEAM8(t *testing.T) {
	q := url.Values{}
	q.Set("client_id", "Esite")
	q.Set("redirect_uri", "https://rp.example/cb")
	q.Set("nonce", "n1")
	q.Set("scope", "openid profile email")
	q.Set("vp_format", "acdc")
	req := httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+q.Encode(), nil)
	auth, err := ParseAuthRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if auth.VPFormat != VPFormatACDC {
		t.Fatalf("vp_format = %s", auth.VPFormat)
	}
	if len(auth.RequestedDisclosures) < 2 {
		t.Fatalf("disclosures = %v", auth.RequestedDisclosures)
	}
	bundle := auth.ToChallengeBundle("http://relay/oobi/Esite", "https://rp.example", "https://rp.example/cb", "sess")
	if bundle.Nonce != "n1" || bundle.SiteAID != "Esite" {
		t.Fatalf("bundle mapping: %+v", bundle)
	}
}

func TestExpandScopesNamespacedClaims(t *testing.T) {
	fields := ExpandScopes("openid", []string{ClaimNamespace + "/employee_id"})
	if len(fields) != 1 || fields[0] != "employee_id" {
		t.Fatalf("fields = %v", fields)
	}
}
