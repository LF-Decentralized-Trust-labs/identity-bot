package login

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	keri "github.com/grapeid/keri-go"
)

// aWitness is a non-transferable witness key, which is also its identifier.
func aWitness(t *testing.T) aSigner {
	t.Helper()
	s, err := keri.GenerateSigner(false)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return aSigner{s: s, pub: p}
}

// receipt is w's receipt for the event raw: its signature over the event's
// identifier, the form drivers.VerifyReceipt checks.
func receipt(t *testing.T, w aSigner, raw []byte) (said string, r map[string]interface{}) {
	t.Helper()
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	return ev.SAID, map[string]interface{}{"witness_aid": w.pub, "cesr_signature": w.sign(t, []byte(ev.SAID))}
}

// serveWithReceipts serves l with the given witness receipts beside it.
func serveWithReceipts(t *testing.T, l signedLog, receipts map[string][]map[string]interface{}) *httptest.Server {
	t.Helper()
	var raws []string
	for _, r := range l.raws {
		raws = append(raws, base64.StdEncoding.EncodeToString(r))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"aid": l.aid, "raw_events_b64": raws, "cesr_signatures": l.sigs, "receipts": receipts,
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// aSiteDelegatedBy builds a site delegated by delegatorAID, and the
// interaction at sn approving it, signed by key, after prior.
func aSiteDelegatedBy(t *testing.T, delegatorAID, priorSAID string, sn int, key aSigner) (site signedLog, ixn []byte, ixnSig string) {
	t.Helper()
	sk, sn2 := newSigner(t), newSigner(t)
	dip, err := keri.BuildDelegatedInception(keri.DelegationInput{
		Delegator: delegatorAID, Keys: []string{sk.pub}, NextDigests: []string{sn2.digest(t)},
	})
	if err != nil {
		t.Fatal(err)
	}
	dipEv, _ := keri.ParseEvent(dip)
	site = signedLog{aid: dipEv.Identifier, raws: [][]byte{dip}, sigs: []string{sk.sign(t, dip)}}
	seal, _ := json.Marshal(struct {
		I string `json:"i"`
		S string `json:"s"`
		D string `json:"d"`
	}{dipEv.Identifier, "0", dipEv.SAID})
	ixn, err = keri.BuildInteraction(keri.InteractionInput{
		Prefix: delegatorAID, PriorSAID: priorSAID, SN: sn, Data: []json.RawMessage{seal},
	})
	if err != nil {
		t.Fatal(err)
	}
	return site, ixn, key.sign(t, ixn)
}

func checkAnchor(t *testing.T, site signedLog, delegatorAID, delegatorURL string) error {
	t.Helper()
	h := &Handler{HTTPClient: &http.Client{Timeout: 5 * time.Second}}
	siteSrv := site.serve(t)
	id, err := IdentityFromOOBI(h.HTTPClient, siteSrv.URL+"/oobi/"+site.aid, site.aid)
	if err != nil {
		t.Fatal(err)
	}
	return h.verifyDelegationAnchor(anchoredBundle(site.aid, delegatorAID, delegatorURL), id)
}

// An organisation that names witnesses rotates its key away from k0. Whoever
// still holds k0 builds a branch from the inception, approving a site of their
// own, and serves it at the organisation's introduction with the inception's
// real receipt. The branch validates, and its signer once held the key, but no
// witness receipted it, because the witnesses saw the rotation in its place.
// The site is not the organisation's.
func TestARetiredDelegatorKeyApprovesNoSite(t *testing.T) {
	w := aWitness(t)
	k0, k1, k2 := newSigner(t), newSigner(t), newSigner(t)
	org := anInception(t, k0, k1, []string{w.pub})
	icpEv, _ := keri.ParseEvent(org.raws[0])
	icpSAID, icpReceipt := receipt(t, w, org.raws[0])

	// The organisation's real history: rotated to k1, witnessed.
	rot, err := keri.BuildRotation(keri.RotationInput{
		Prefix: org.aid, Keys: []string{k1.pub}, PriorSAID: icpEv.SAID, SN: 1,
		NextDigests: []string{k2.digest(t)}, PriorWitnesses: []string{w.pub},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = rot

	// The thief's branch: the inception, then an approval at the same place,
	// signed with the retired k0.
	site, ixn, ixnSig := aSiteDelegatedBy(t, org.aid, icpEv.SAID, 1, k0)
	branch := signedLog{aid: org.aid, raws: [][]byte{org.raws[0], ixn}, sigs: []string{org.sigs[0], ixnSig}}
	srv := serveWithReceipts(t, branch, map[string][]map[string]interface{}{icpSAID: {icpReceipt}})

	err = checkAnchor(t, site, org.aid, srv.URL+"/oobi/"+org.aid)
	if err == nil || !strings.Contains(err.Error(), "retired") {
		t.Fatalf("an approval signed by a key the organisation had rotated away was honoured: %v", err)
	}
}

// A key registry that never answers does not hold up the person's consent
// screen: publishing runs beside the sign-in.
func TestARegistryThatHangsDoesNotDelayTheConsentScreen(t *testing.T) {
	siteAID, siteSeed, siteLog := aRealIdentity(t)
	kl, err := DecodeKeyLog(siteLog)
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	var srv *httptest.Server
	const token = "a-session"
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/oobi/"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"aid": siteAID, "raw_events_b64": kl.RawEventsB64, "cesr_signatures": kl.CesrSignatures,
			})
		case r.URL.Path == "/i/"+token:
			b := ChallengeBundle{V: "ASK1", T: 1, SiteAID: siteAID, SiteOOBI: srv.URL + "/oobi/" + siteAID,
				Audience: "https://site.example", Nonce: "n", Dt: time.Now().UTC().Format(time.RFC3339),
				Expiry:               time.Now().Add(time.Minute).UTC().Format(time.RFC3339),
				RequestedDisclosures: []string{}, RequestedCredentials: []RequestedCredential{},
				CallbackURL: srv.URL + "/callback", SessionToken: token}
			if err := SignChallengeForAsset(&b, siteSeed); err != nil {
				t.Error(err)
			}
			_ = json.NewEncoder(w).Encode(b)
		default: // the registry: never answers
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}
	}))
	defer srv.Close()
	defer close(release) // before the server closes, so the hung registry lets go

	h, _ := aRelationshipFor(t, srv.URL+"/oobi/"+siteAID)
	prepared := make(chan error, 1)
	go func() {
		_, _, preview, err := h.prepareLogin(StartLoginRequest{SessionToken: token, RPSessionURL: srv.URL})
		if err == nil && preview == nil {
			err = fmt.Errorf("no preview")
		}
		prepared <- err
	}()
	select {
	case err := <-prepared:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("a registry that never answers held the consent screen")
	}
}

// The same organisation's real approval, receipted by its witness, is honoured.
func TestAWitnessedDelegatorsApprovalIsHonoured(t *testing.T) {
	w := aWitness(t)
	k0, k1 := newSigner(t), newSigner(t)
	org := anInception(t, k0, k1, []string{w.pub})
	icpEv, _ := keri.ParseEvent(org.raws[0])
	site, ixn, ixnSig := aSiteDelegatedBy(t, org.aid, icpEv.SAID, 1, k0)
	full := signedLog{aid: org.aid, raws: [][]byte{org.raws[0], ixn}, sigs: []string{org.sigs[0], ixnSig}}
	icpSAID, icpR := receipt(t, w, org.raws[0])
	ixnSAID, ixnR := receipt(t, w, ixn)
	srv := serveWithReceipts(t, full, map[string][]map[string]interface{}{icpSAID: {icpR}, ixnSAID: {ixnR}})

	if err := checkAnchor(t, site, org.aid, srv.URL+"/oobi/"+org.aid); err != nil {
		t.Fatalf("a witnessed organisation's own approval was refused: %v", err)
	}
}
