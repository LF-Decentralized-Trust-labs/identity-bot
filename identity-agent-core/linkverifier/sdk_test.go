package linkverifier

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"identity-agent-core/didwebs"
)

const testAID = "EAliceTestAID0123456789ABCDEFGHIJKLMN"

type mockReplay struct {
	ok bool
}

func (m *mockReplay) ValidateKEL(ctx context.Context, aid string, events []map[string]interface{}) (bool, string, []string, error) {
	_ = ctx
	_ = aid
	_ = events
	return m.ok, "Dmockkey", nil, nil
}

type rewriteTransport struct {
	target string
}

func (t rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	u, _ := url.Parse(t.target)
	req.URL.Scheme = u.Scheme
	req.URL.Host = u.Host
	return http.DefaultTransport.RoundTrip(req)
}

func rewriteHTTPSClient(srv *httptest.Server) *http.Client {
	return &http.Client{Transport: rewriteTransport{target: srv.URL}}
}

func publisherHandler(routePrefix string, kel []map[string]interface{}, didDoc map[string]interface{}, didSeq, cesrSeq int, cesrComplete bool) http.HandlerFunc {
	kelBytes, _ := json.Marshal(kel)
	didBytes, _ := json.Marshal(didDoc)
	base := strings.TrimSuffix(routePrefix, "/")
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == base+"/did.json":
			w.Header().Set("X-Keri-Keystate-Seq", itoa(didSeq))
			w.Write(didBytes)
		case r.URL.Path == base+"/keri.cesr":
			w.Header().Set("X-Keri-Keystate-Seq", itoa(cesrSeq))
			if !cesrComplete {
				w.Header().Set("X-Keri-Cesr-Complete", "false")
			}
			w.Write(kelBytes)
		default:
			http.NotFound(w, r)
		}
	}
}

func itoa(n int) string {
	if n < 0 {
		return ""
	}
	if n == 0 {
		return "0"
	}
	b := []byte{}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

type publisherFixture struct {
	sdk  *SDK
	did  string
	done func()
}

func startPublisher(t *testing.T, kel []map[string]interface{}, didDoc map[string]interface{}, didSeq, cesrSeq int, cesrComplete, replayOK bool, cfg Config) publisherFixture {
	t.Helper()
	var inner http.Handler = http.NotFoundHandler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	did := "did:webs:127.0.0.1:" + testAID
	if didDoc != nil {
		didDoc["id"] = did
	}
	artifactURLs, err := didwebs.DeriveFromDID(did)
	if err != nil {
		t.Fatal(err)
	}
	p, err := url.Parse(artifactURLs.DidJSONURL)
	if err != nil {
		t.Fatal(err)
	}
	routePrefix := strings.TrimSuffix(p.Path, "/did.json")
	inner = publisherHandler(routePrefix, kel, didDoc, didSeq, cesrSeq, cesrComplete)

	resolver := didwebs.NewResolver(&mockReplay{ok: replayOK})
	resolver.HTTPClient = rewriteHTTPSClient(srv)
	if cfg.EagerCap == 0 {
		cfg.EagerCap = 20
	}
	return publisherFixture{
		sdk:  &SDK{resolver: resolver, cache: newCache(), cfg: cfg},
		did:  did,
		done: srv.Close,
	}
}

func defaultKel() []map[string]interface{} {
	return []map[string]interface{}{
		{"v": "KERI10JSON000256_", "t": "icp", "i": testAID, "s": "0", "k": []string{"Dkey1"}},
	}
}

func defaultDidDoc() map[string]interface{} {
	return map[string]interface{}{
		"verificationMethod": []map[string]interface{}{
			{"id": "#key-1", "type": "Ed25519VerificationKey2020"},
		},
	}
}

func TestVerifyDidWebsVerified(t *testing.T) {
	fx := startPublisher(t, defaultKel(), defaultDidDoc(), 0, 0, true, true, Config{})
	result, err := fx.sdk.Verify(context.Background(), VerifyRequest{
		Input: fx.did, InputKind: InputDIDWebs, Flow: FlowLink, Tier: TierFree,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != OutcomeVerified {
		t.Fatalf("outcome=%s want verified", result.Outcome)
	}
	if result.Ownership == nil {
		t.Fatal("link flow should include ownership")
	}
	if result.GrapeScore != nil {
		t.Fatal("free tier must omit grape_score")
	}
	if result.BandStyle != "generic" {
		t.Fatalf("band_style=%q want generic", result.BandStyle)
	}
}

func TestVerifyBadgeFlowOmitsOwnership(t *testing.T) {
	fx := startPublisher(t, defaultKel(), defaultDidDoc(), 0, 0, true, true, Config{})
	result, err := fx.sdk.Verify(context.Background(), VerifyRequest{Input: fx.did, Flow: FlowBadge})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != OutcomeVerified {
		t.Fatalf("outcome=%s", result.Outcome)
	}
	if result.Ownership != nil {
		t.Fatal("badge flow must not include ownership")
	}
}

func TestVerifyTamperedReplayFailure(t *testing.T) {
	fx := startPublisher(t, defaultKel(), defaultDidDoc(), 0, 0, true, false, Config{})
	result, err := fx.sdk.Verify(context.Background(), VerifyRequest{Input: fx.did, Flow: FlowLink})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != OutcomeTampered {
		t.Fatalf("outcome=%s want tampered", result.Outcome)
	}
	if result.Band != "red" {
		t.Fatalf("band=%s want red", result.Band)
	}
}

func TestVerifySeqMismatchUnverified(t *testing.T) {
	fx := startPublisher(t, defaultKel(), defaultDidDoc(), 0, 1, true, true, Config{})
	result, err := fx.sdk.Verify(context.Background(), VerifyRequest{Input: fx.did, Flow: FlowLink})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != OutcomeUnverified {
		t.Fatalf("seq mismatch outcome=%s want unverified", result.Outcome)
	}
}

func TestVerifyPartialFetchUnverified(t *testing.T) {
	didDoc := defaultDidDoc()
	did := "did:webs:127.0.0.1:" + testAID
	didDoc["id"] = did
	didBytes, _ := json.Marshal(didDoc)
	u, _ := didwebs.DeriveFromDID(did)
	p, _ := url.Parse(u.DidJSONURL)
	didPath := p.Path
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == didPath {
			w.Write(didBytes)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	resolver := didwebs.NewResolver(&mockReplay{ok: true})
	resolver.HTTPClient = rewriteHTTPSClient(srv)
	sdk := &SDK{resolver: resolver, cache: newCache()}

	result, err := sdk.Verify(context.Background(), VerifyRequest{Input: did})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != OutcomeUnverified {
		t.Fatalf("partial fetch outcome=%s want unverified", result.Outcome)
	}
}

func TestVerifyIncompleteWitnesses(t *testing.T) {
	fx := startPublisher(t, defaultKel(), defaultDidDoc(), 0, 0, false, true, Config{})
	result, err := fx.sdk.Verify(context.Background(), VerifyRequest{Input: fx.did})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != OutcomeIncomplete {
		t.Fatalf("outcome=%s want incomplete", result.Outcome)
	}
	if result.Band != "amber" {
		t.Fatalf("band=%s want amber", result.Band)
	}
}

func TestVerifyUnverifiedNoPublication(t *testing.T) {
	sdk := New(nil, Config{})
	result, err := sdk.Verify(context.Background(), VerifyRequest{
		Input: "https://example.invalid/no-keri-here", Flow: FlowBadge,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != OutcomeUnverified {
		t.Fatalf("outcome=%s", result.Outcome)
	}
	if result.ContactCorrelation != nil {
		t.Fatal("in-process SDK must not populate contact_correlation")
	}
}

func TestGatedTierSilentDegrade(t *testing.T) {
	sdk := New(nil, Config{GrapeScoreProviderActive: false})
	result, err := sdk.Verify(context.Background(), VerifyRequest{
		Input: "https://example.invalid", Tier: TierGated,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.GrapeScore != nil {
		t.Fatal("gated without entitlement must omit score")
	}
	if result.BandStyle != "generic" {
		t.Fatalf("band_style=%q want generic on degrade", result.BandStyle)
	}
}

func TestGatedTierWithProvider(t *testing.T) {
	fx := startPublisher(t, defaultKel(), defaultDidDoc(), 0, 0, true, true, Config{GrapeScoreProviderActive: true})
	result, err := fx.sdk.Verify(context.Background(), VerifyRequest{
		Input: fx.did, Tier: TierGated, Flow: FlowBadge,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.GrapeScore == nil || result.Badge == nil {
		t.Fatal("gated with provider should include score and badge")
	}
}

func TestVerifyWithContacts(t *testing.T) {
	fx := startPublisher(t, defaultKel(), defaultDidDoc(), 0, 0, true, true, Config{
		ContactLookup: func(a string) (bool, string) {
			if a == testAID {
				return true, "Alice"
			}
			return false, ""
		},
	})
	result, err := fx.sdk.VerifyWithContacts(context.Background(), VerifyRequest{Input: fx.did, Flow: FlowLink})
	if err != nil {
		t.Fatal(err)
	}
	if result.ContactCorrelation == nil || *result.ContactCorrelation != "known" {
		t.Fatalf("contact_correlation=%v want known", result.ContactCorrelation)
	}
}

func TestVerifyInProcessNoContactCorrelation(t *testing.T) {
	fx := startPublisher(t, defaultKel(), defaultDidDoc(), 0, 0, true, true, Config{
		ContactLookup: func(a string) (bool, string) { return true, "Alice" },
	})
	result, err := fx.sdk.Verify(context.Background(), VerifyRequest{Input: fx.did})
	if err != nil {
		t.Fatal(err)
	}
	if result.ContactCorrelation != nil {
		t.Fatal("in-process Verify must not populate contact_correlation")
	}
}