package login

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	keri "github.com/grapeid/keri-go"
)

// aSigner is a fresh Ed25519 key, its public key in CESR, and a way to sign
// event bytes the way an identity publishes them.
type aSigner struct {
	s   keri.Signer
	pub string
}

func newSigner(t *testing.T) aSigner {
	t.Helper()
	s, err := keri.GenerateSigner(true)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return aSigner{s: s, pub: p}
}

func (a aSigner) digest(t *testing.T) string {
	t.Helper()
	d, err := keri.NextDigest(a.pub)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func (a aSigner) sign(t *testing.T, raw []byte) string {
	t.Helper()
	sig, err := a.s.Sign(raw)
	if err != nil {
		t.Fatal(err)
	}
	q, err := keri.MatterQB64(keri.CodeEd25519Sig, sig)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// signedLog is an identity's log as an introduction serves it.
type signedLog struct {
	aid  string
	raws [][]byte
	sigs []string
}

func (l signedLog) serve(t *testing.T) *httptest.Server {
	t.Helper()
	var raws []string
	for _, r := range l.raws {
		raws = append(raws, base64.StdEncoding.EncodeToString(r))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"aid": l.aid, "raw_events_b64": raws, "cesr_signatures": l.sigs,
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func anInception(t *testing.T, key, next aSigner, witnesses []string) signedLog {
	t.Helper()
	icp, err := keri.BuildInception(keri.InceptionInput{
		Keys: []string{key.pub}, NextDigests: []string{next.digest(t)},
		Witnesses: witnesses, Derivation: "self-addressing",
	})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := keri.ParseEvent(icp)
	if err != nil {
		t.Fatal(err)
	}
	return signedLog{aid: ev.Identifier, raws: [][]byte{icp}, sigs: []string{key.sign(t, icp)}}
}

// aDelegatedSite is a site whose inception names delegator, and the
// delegator's log; approved says whether the delegator anchored it.
func aDelegatedSite(t *testing.T, approved bool) (site, delegator signedLog) {
	t.Helper()
	dk, dn := newSigner(t), newSigner(t)
	delegator = anInception(t, dk, dn, nil)

	sk, sn := newSigner(t), newSigner(t)
	dip, err := keri.BuildDelegatedInception(keri.DelegationInput{
		Delegator: delegator.aid, Keys: []string{sk.pub}, NextDigests: []string{sn.digest(t)},
	})
	if err != nil {
		t.Fatal(err)
	}
	dipEv, err := keri.ParseEvent(dip)
	if err != nil {
		t.Fatal(err)
	}
	site = signedLog{aid: dipEv.Identifier, raws: [][]byte{dip}, sigs: []string{sk.sign(t, dip)}}

	if approved {
		icpEv, _ := keri.ParseEvent(delegator.raws[0])
		seal, _ := json.Marshal(struct {
			I string `json:"i"`
			S string `json:"s"`
			D string `json:"d"`
		}{dipEv.Identifier, "0", dipEv.SAID})
		ixn, err := keri.BuildInteraction(keri.InteractionInput{
			Prefix: delegator.aid, PriorSAID: icpEv.SAID, SN: 1, Data: []json.RawMessage{seal},
		})
		if err != nil {
			t.Fatal(err)
		}
		delegator.raws = append(delegator.raws, ixn)
		delegator.sigs = append(delegator.sigs, dk.sign(t, ixn))
	}
	return site, delegator
}

func anchoredBundle(site, delegatorAID, delegatorOOBI string) *ChallengeBundle {
	return &ChallengeBundle{
		SiteAID: site, RelationshipAnchorAID: delegatorAID, RelationshipAnchorOOBI: delegatorOOBI,
	}
}

// A site the organisation really delegated, and whose delegation the
// organisation's own log approves, is honoured as the organisation's.
func TestASiteTheDelegatorApprovedIsHonoured(t *testing.T) {
	site, delegator := aDelegatedSite(t, true)
	h := &Handler{HTTPClient: &http.Client{Timeout: 5 * time.Second}}
	siteSrv, delSrv := site.serve(t), delegator.serve(t)
	id, err := IdentityFromOOBI(h.HTTPClient, siteSrv.URL+"/oobi/"+site.aid, site.aid)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.verifyDelegationAnchor(anchoredBundle(site.aid, delegator.aid, delSrv.URL+"/oobi/"+delegator.aid), id); err != nil {
		t.Fatalf("a delegation the delegator approved was refused: %v", err)
	}
}

// The attack: a site writes "delegated by" the organisation into its own
// inception, which costs nothing, and the organisation never approved it. It
// must not be handed the organisation's members' identities.
func TestASiteThatOnlyClaimsADelegatorIsRefused(t *testing.T) {
	site, delegator := aDelegatedSite(t, false)
	h := &Handler{HTTPClient: &http.Client{Timeout: 5 * time.Second}}
	siteSrv, delSrv := site.serve(t), delegator.serve(t)
	id, err := IdentityFromOOBI(h.HTTPClient, siteSrv.URL+"/oobi/"+site.aid, site.aid)
	if err != nil {
		t.Fatal(err)
	}
	err = h.verifyDelegationAnchor(anchoredBundle(site.aid, delegator.aid, delSrv.URL+"/oobi/"+delegator.aid), id)
	if err == nil {
		t.Fatal("a site claiming a delegator that never approved it was honoured as that delegator's")
	}
	if !strings.Contains(err.Error(), "never approved") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

// What the anchor is read from is the site's verified log. A plain site
// serving a made-up "dip" record beside its real, undelegated log gains
// nothing, because the bytes that were checked say icp.
func TestADelegationIsReadFromTheVerifiedLogNotARecordBesideIt(t *testing.T) {
	k, n := newSigner(t), newSigner(t)
	plain := anInception(t, k, n, nil)
	_, delegator := aDelegatedSite(t, true)
	var raws []string
	for _, r := range plain.raws {
		raws = append(raws, base64.StdEncoding.EncodeToString(r))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"aid": plain.aid, "raw_events_b64": raws, "cesr_signatures": plain.sigs,
			"kel": []map[string]interface{}{{"t": "dip", "i": plain.aid, "di": delegator.aid}},
		})
	}))
	defer srv.Close()
	h := &Handler{HTTPClient: &http.Client{Timeout: 5 * time.Second}}
	id, err := IdentityFromOOBI(h.HTTPClient, srv.URL+"/oobi/"+plain.aid, plain.aid)
	if err != nil {
		t.Fatal(err)
	}
	delSrv := delegator.serve(t)
	if err := h.verifyDelegationAnchor(anchoredBundle(plain.aid, delegator.aid, delSrv.URL+"/oobi/"+delegator.aid), id); err == nil {
		t.Fatal("an undelegated site was honoured as delegated on the strength of a record it served beside its log")
	}
}

// A challenge that names an anchor but no introduction for it cannot have
// its delegation checked, and is refused rather than taken on its word.
func TestAnAnchorWithNoIntroductionIsRefused(t *testing.T) {
	site, delegator := aDelegatedSite(t, true)
	h := &Handler{HTTPClient: &http.Client{Timeout: 5 * time.Second}}
	id, err := IdentityFromOOBI(h.HTTPClient, site.serve(t).URL+"/oobi/"+site.aid, site.aid)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.verifyDelegationAnchor(anchoredBundle(site.aid, delegator.aid, ""), id); err == nil {
		t.Fatal("an anchor with no introduction was honoured")
	}
}
