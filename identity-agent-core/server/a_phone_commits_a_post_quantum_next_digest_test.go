package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"identity-agent-core/backup"
	"identity-agent-core/enrolsecret"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/secureenclave"

	keri "github.com/grapeid/keri-go"
)

// An owner's phone commits to a post-quantum key beside each classical key it
// will rotate into (ADR-061 section 6), and the ownership change that carries
// those commitments is applied.

// aRealPhone is a phone's Identity Agent that agreed to own an organisation: what
// it sent, and the keys it holds for the organisation.
type aRealPhone struct {
	s     *CoreServer
	body  map[string]string
	rel   *login.SiteRelationship
	root  []byte
	token string
}

func aRealPhoneAccepting(t *testing.T) *aRealPhone {
	t.Helper()
	got := map[string]string{}
	org := captureRedeem(t, &got)
	t.Cleanup(org.Close)
	s := agentWithDerivedIdentity(t)
	if err := s.initLoginHandler(); err != nil {
		t.Skipf("login engine unavailable: %v", err)
	}
	if err := signOrgRedeemFor(t, s, org.URL); err != nil {
		t.Fatalf("the phone could not accept: %v", err)
	}
	rel, err := s.loginHandler.GetOrCreateRelationship("EORGAID", &login.ChallengeBundle{SiteAID: "EORGAID"})
	if err != nil {
		t.Fatal(err)
	}
	root, err := secureenclave.LoadRootSeed(s.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	return &aRealPhone{s: s, body: got, rel: rel, root: root, token: "tok"}
}

// key is the phone's classical key of [gen] for the organisation.
func (p *aRealPhone) key(t *testing.T, gen int) aSigner {
	t.Helper()
	sd, err := backup.DerivePairwiseSeed(p.root, p.rel.RelationshipIndex, gen)
	if err != nil {
		t.Fatal(err)
	}
	return aSigner{sd}
}

// What the phone sends: a post-quantum digest for the key it rotates into and
// one for the key after, each a digest of the key the documented path gives,
// none the classical digest again.
func TestAnOwnersPhoneSendsAPostQuantumDigestBesideEachClassicalOne(t *testing.T) {
	p := aRealPhoneAccepting(t)
	for _, c := range []struct {
		gen  int
		sent string
		name string
	}{{1, p.body["next_post_quantum_digest"], "next"}, {2, p.body["after_next_post_quantum_digest"], "after_next"}} {
		if !isABlake3Digest(c.sent) {
			t.Fatalf("the %s post-quantum digest sent is %q, not a digest", c.name, c.sent)
		}
		// Recomputed here from the path the ADR names, not through the code under test.
		sd, err := backup.DerivePairwiseSeed(p.root, p.rel.RelationshipIndex, backup.PostQuantumBranch+c.gen)
		if err != nil {
			t.Fatal(err)
		}
		pq, err := iacrypto.PostQuantumNextKeyFromSeed(sd)
		if err != nil {
			t.Fatal(err)
		}
		if pq.Digest != c.sent {
			t.Errorf("the %s post-quantum digest is not the one of the key at m/44'/0'/0'/%d'/%d'", c.name, p.rel.RelationshipIndex, backup.PostQuantumBranch+c.gen)
		}
		if classical := digestOfSeed(t, p.key(t, c.gen).seed); classical == c.sent {
			t.Errorf("the %s post-quantum digest is the classical one again", c.name)
		}
	}
	if p.body["next_post_quantum_digest"] == p.body["after_next_post_quantum_digest"] {
		t.Error("one post-quantum key stands behind both rotations")
	}
	// The classical digest this phone will insist on is that of the key it sent.
	if want := digestOfSeed(t, p.key(t, 1).seed); verkeyOf(p.key(t, 1).seed) != p.body["next_public_key"] || want == "" {
		t.Error("the classical next key sent is not the key of generation 1")
	}
}

// A secret is never behind two keys: the post-quantum seeds of a relationship
// are not its classical seeds, and not the identity's own post-quantum seeds
// (ADR-061 section 1).
func TestAPhonesPostQuantumKeysAreNotAnyOtherKey(t *testing.T) {
	p := aRealPhoneAccepting(t)
	seen := map[string]string{}
	add := func(name string, sd []byte, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		if other, dup := seen[string(sd)]; dup {
			t.Errorf("%s and %s are the same 32 bytes", name, other)
		}
		seen[string(sd)] = name
	}
	for g := 0; g <= 3; g++ {
		sd, err := backup.DerivePairwiseSeed(p.root, p.rel.RelationshipIndex, g)
		add("classical", sd, err)
		sd, err = backup.DerivePairwisePostQuantumSeed(p.root, p.rel.RelationshipIndex, g)
		add("relationship post-quantum", sd, err)
		sd, err = backup.DerivePairwiseSeed(p.root, backup.PostQuantumBranch, g)
		add("identity post-quantum", sd, err)
	}
	if _, err := backup.DerivePairwisePostQuantumSeed(p.root, p.rel.RelationshipIndex, -1); err == nil {
		t.Error("a negative generation was derived")
	}
}

// Two phones, each with its own phrase, accept a hand-over; every key and
// digest the organisation holds for them is what they sent. The ceremony then
// goes through both rotations, each phone signing as its own key at the place
// the event gives it, and is applied with a log keri-go verifies: four digests
// under one weighted share per owner, and neither phone's post-quantum
// commitment lost between the two rotations.
func TestAHandOverWithPostQuantumDigestsFromRealPhonesIsApplied(t *testing.T) {
	pa, pc := aRealPhoneAccepting(t), aRealPhoneAccepting(t)
	pa.body["pairwise_aid"], pc.body["pairwise_aid"] = deviceA, deviceC
	w := &aCeremonyWorld{}
	w.begin(t, true, func(w *aCeremonyWorld) []CeremonyInvitee {
		return []CeremonyInvitee{
			{Name: "A", TokenDigest: enrolsecret.Digest("tok-a")},
			{Name: "C", TokenDigest: enrolsecret.Digest("tok-c")},
		}
	})
	var last *OwnerCeremony
	var complete bool
	for _, a := range []struct {
		tok string
		p   *aRealPhone
	}{{"tok-a", pa}, {"tok-c", pc}} {
		var err error
		last, complete, err = w.s.recordAcceptance(a.tok, a.p.body["pairwise_aid"], a.p.body["public_key"], a.p.body["next_public_key"], CeremonyExtras{
			NextPostQuantumDigest:      a.p.body["next_post_quantum_digest"],
			AfterNextPublicKey:         a.p.body["after_next_public_key"],
			AfterNextPostQuantumDigest: a.p.body["after_next_post_quantum_digest"],
		})
		if err != nil {
			t.Fatalf("the organisation refused what a real phone sent: %v", err)
		}
	}
	if !complete {
		t.Fatal("both phones accepted and the ceremony did not complete")
	}
	w.s.completeCeremonyIfReady(last)
	w.a = []aSigner{pa.key(t, 0), pa.key(t, 1), pa.key(t, 2)}
	w.c = []aSigner{pc.key(t, 0), pc.key(t, 1), pc.key(t, 2)}

	raw1, d1, code := w.fetch(t, "tok-a")
	if code != http.StatusOK {
		t.Fatalf("the first rotation was not offered: %d (%s)", code, w.ceremony(t).Detail)
	}
	ev1, _ := keri.ParseEvent(raw1)
	var body struct {
		Nt json.RawMessage `json:"nt"`
	}
	_ = json.Unmarshal(raw1, &body)
	if len(ev1.NextDigest) != 4 || string(body.Nt) != `[{"1/2":["1","1"]},{"1/2":["1","1"]}]` {
		t.Fatalf("the first rotation commits to %d digests under nt %s: want both phones' classical and post-quantum digests under one share each", len(ev1.NextDigest), body.Nt)
	}
	for _, p := range []*aRealPhone{pa, pc} {
		for _, d := range []string{digestOfSeed(t, p.key(t, 1).seed), p.body["next_post_quantum_digest"]} {
			placeOfDigest(t, raw1, d)
		}
	}
	w.sign(t, "tok-a", d1, w.a[0].at(t, raw1, 1, -1))
	if code, out := w.sign(t, "tok-c", d1, w.c[0].at(t, raw1, 2, -1)); code != http.StatusCreated {
		t.Fatalf("%d %v", code, out)
	}
	raw2, d2, code := w.fetch(t, "tok-a")
	if code != http.StatusOK {
		t.Fatalf("the second rotation was not offered: %d", code)
	}
	ev2, _ := keri.ParseEvent(raw2)
	if len(ev2.NextDigest) != 4 {
		t.Fatalf("the second rotation commits to %d digests, want both phones' two", len(ev2.NextDigest))
	}
	for _, p := range []*aRealPhone{pa, pc} {
		for _, d := range []string{digestOfSeed(t, p.key(t, 2).seed), p.body["after_next_post_quantum_digest"]} {
			placeOfDigest(t, raw2, d)
		}
	}
	ia, ic := placeOfDigest(t, raw1, digestOfSeed(t, w.a[1].seed)), placeOfDigest(t, raw1, digestOfSeed(t, w.c[1].seed))
	w.sign(t, "tok-a", d2, w.a[1].at(t, raw2, 0, ia))
	if code, out := w.sign(t, "tok-c", d2, w.c[1].at(t, raw2, 1, ic)); code != http.StatusCreated || out["applied"] != true {
		t.Fatalf("both phones signed the second rotation and the change is not applied: %d %v", code, out)
	}
	if c := w.ceremony(t); c.Status != ceremonyApplied {
		t.Fatalf("the ceremony is %q (%s)", c.Status, c.Detail)
	}
}

// What the organisation refuses of what an owner's device sent.
func TestTheOrganisationRefusesAPostQuantumDigestThatIsNotOne(t *testing.T) {
	good := aRealPhoneAccepting(t).body
	next := good["next_public_key"]
	classical, _ := keri.NextDigest(next)
	ok := func(handOver bool, more CeremonyExtras) string { return checkTheDigestsSent(handOver, next, more) }
	full := CeremonyExtras{NextPostQuantumDigest: good["next_post_quantum_digest"], AfterNextPostQuantumDigest: good["after_next_post_quantum_digest"]}
	if why := ok(true, full); why != "" {
		t.Fatalf("what a real phone sent was refused: %s", why)
	}
	if why := ok(true, CeremonyExtras{}); why != "" {
		t.Errorf("an owner with no post-quantum commitment at all was refused: %s", why)
	}
	for name, more := range map[string]CeremonyExtras{
		"text that is not a digest":        {NextPostQuantumDigest: "not-a-digest", AfterNextPostQuantumDigest: full.AfterNextPostQuantumDigest},
		"the classical digest again":       {NextPostQuantumDigest: classical, AfterNextPostQuantumDigest: full.AfterNextPostQuantumDigest},
		"no partner in a hand-over":        {NextPostQuantumDigest: full.NextPostQuantumDigest},
		"a partner without the first":      {AfterNextPostQuantumDigest: full.AfterNextPostQuantumDigest},
		"one digest for both rotations":    {NextPostQuantumDigest: full.NextPostQuantumDigest, AfterNextPostQuantumDigest: full.NextPostQuantumDigest},
		"a second that is not a digest":    {NextPostQuantumDigest: full.NextPostQuantumDigest, AfterNextPostQuantumDigest: strings.Repeat("E", 43)},
		"a digest with a character no one": {NextPostQuantumDigest: "E" + strings.Repeat("!", 43), AfterNextPostQuantumDigest: full.AfterNextPostQuantumDigest},
	} {
		if ok(true, more) == "" {
			t.Errorf("%s was taken", name)
		}
	}
	// The same through the route: a refused acceptance records nothing and the
	// person who sent it can send it again.
	w := (&aCeremonyWorld{}).begin(t, true, func(*aCeremonyWorld) []CeremonyInvitee {
		return []CeremonyInvitee{{Name: "A", TokenDigest: enrolsecret.Digest("tok-a")}}
	})
	if _, _, err := w.s.recordAcceptance("tok-a", deviceA, good["public_key"], next, CeremonyExtras{
		NextPostQuantumDigest: "junk", AfterNextPublicKey: good["after_next_public_key"], AfterNextPostQuantumDigest: full.AfterNextPostQuantumDigest}); err == nil {
		t.Fatal("a junk digest was recorded")
	}
	if w.ceremony(t).Invited[0].Accepted() {
		t.Fatal("the refused acceptance was recorded anyway")
	}
}

// A phone signs only a rotation that commits it to the keys it derived: its
// classical next key AND its post-quantum partner. Each of these is an attack
// by an organisation that wants the owner's signature on something else.
func TestAPhoneWillNotSignARotationThatDropsItsCommitments(t *testing.T) {
	d := aCeremonyDeviceOf(t)
	aid := d.org.aid
	mine0, mine1 := d.commits(t, 1), d.commits(t, 2)
	reveal := []ed25519.PublicKey{d.pub(t, 0)}
	other, _ := keri.NextDigest(verkeyOf(signerSeeds(1, 70)[0].seed))
	otherPQ := p2(t)

	for name, next := range map[string][]string{
		"the post-quantum commitment left out":             {mine0.Classical, mine1.Classical, mine1.PostQuantum},
		"the classical commitment left out":                {mine0.PostQuantum, mine1.Classical, mine1.PostQuantum},
		"the post-quantum commitment replaced by another":  {mine0.Classical, otherPQ},
		"the classical commitment replaced by another":     {other, mine0.PostQuantum},
		"commitments for the wrong generation (the first)": {d.commits(t, 0).Classical, d.commits(t, 0).PostQuantum},
		"no commitment at all":                             {other},
	} {
		raw, _ := ceremonyRotationCommitting(t, aid, 1, d.org.icpSAID, reveal, next)
		if w := d.ask("tok", 0, raw); w.Code != http.StatusConflict || signedBy(w, d.pub(t, 0), raw) {
			t.Errorf("%s: answered %d (%s), want a refusal and no signature", name, w.Code, w.Body)
		}
	}
	// The key it will use second commits the same way, one generation on.
	raw1, said := ceremonyRotationCommitting(t, aid, 1, d.org.icpSAID, reveal, []string{mine0.Classical, mine0.PostQuantum})
	if w := d.ask("tok", 0, raw1); !signedBy(w, d.pub(t, 0), raw1) {
		t.Fatalf("a rotation that commits as it should was not signed: %d %s", w.Code, w.Body)
	}
	bad, _ := ceremonyRotationCommitting(t, aid, 2, said, []ed25519.PublicKey{d.pub(t, 1)}, []string{mine1.Classical})
	if w := d.ask("tok", 1, bad); w.Code != http.StatusConflict {
		t.Errorf("a second rotation without the post-quantum commitment was answered %d (%s)", w.Code, w.Body)
	}
	good, _ := ceremonyRotationCommitting(t, aid, 2, said, []ed25519.PublicKey{d.pub(t, 1)}, []string{mine1.Classical, mine1.PostQuantum})
	if w := d.ask("tok", 1, good); !signedBy(w, d.pub(t, 1), good) {
		t.Errorf("the second rotation, committing as it should, was not signed: %d %s", w.Code, w.Body)
	}
}

// p2 is a well-formed post-quantum digest that belongs to nobody here.
func p2(t *testing.T) string {
	t.Helper()
	pq, err := iacrypto.PostQuantumNextKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return pq.Digest
}
