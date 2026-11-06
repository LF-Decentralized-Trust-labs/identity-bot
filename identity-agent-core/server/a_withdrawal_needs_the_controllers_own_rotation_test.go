package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"identity-agent-core/drivers"
	"identity-agent-core/keriengine"
	"identity-agent-core/store"
	"identity-agent-core/witness"

	keri "github.com/grapeid/keri-go"
)

// A witness stands down only on a rotation that is its controller's own: for
// that identity, signed by the keys in force, and in the log the witness holds.
// An event that merely parses, and names the witness in its cut list, is not
// that — anyone can write one.

type rotatingController struct {
	name    string
	aid     string
	eng     *keriengine.Engine
	signers []keri.Signer // current, next, next-next
	icpRaw  []byte
	icpSig  string
	icpSAID string
}

func sign(t *testing.T, s keri.Signer, raw []byte) string {
	t.Helper()
	rs, err := s.Sign(raw)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := keri.MatterQB64(keri.CodeEd25519Sig, rs)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func newRotatingController(t *testing.T, name, witnessKey string) *rotatingController {
	t.Helper()
	return newRotatingControllerWitnessedBy(t, name, witnessKey)
}

// newRotatingControllerWitnessedBy is a controller whose inception names the
// given witnesses, any one of which is enough.
func newRotatingControllerWitnessedBy(t *testing.T, name string, witnessKeys ...string) *rotatingController {
	t.Helper()
	return newRotatingControllerWitnessedByToad(t, name, 1, witnessKeys...)
}

// newRotatingControllerWitnessedByToad is that, with the number of its
// witnesses that must agree (the key log's toad) given.
func newRotatingControllerWitnessedByToad(t *testing.T, name string, toad int, witnessKeys ...string) *rotatingController {
	t.Helper()
	c := &rotatingController{name: name, eng: keriengine.New()}
	var pubs []string
	for i := 0; i < 3; i++ {
		s, err := keri.GenerateSigner(true)
		if err != nil {
			t.Fatal(err)
		}
		p, _ := s.PublicKey()
		c.signers = append(c.signers, s)
		pubs = append(pubs, p)
	}
	icp, err := c.eng.Incept(drivers.InceptionRequest{PublicKey: pubs[0], NextPublicKey: pubs[1],
		Name: name, Witnesses: witnessKeys, Toad: toad})
	if err != nil {
		t.Fatal(err)
	}
	c.icpRaw, _ = base64.StdEncoding.DecodeString(icp.RawBytesB64)
	ev, err := keri.ParseEvent(c.icpRaw)
	if err != nil {
		t.Fatal(err)
	}
	c.aid, c.icpSAID = ev.Identifier, ev.SAID
	c.icpSig = sign(t, c.signers[0], c.icpRaw)
	return c
}

// rotateCutting builds the controller's real rotation, signed by the key it
// reveals, cutting the given witness.
func (c *rotatingController) rotateCutting(t *testing.T, witnessKey string) ([]byte, string) {
	t.Helper()
	p1, _ := c.signers[1].PublicKey()
	p2, _ := c.signers[2].PublicKey()
	rot, err := c.eng.Rotate(drivers.RotationRequest{Name: c.name, NewPublicKey: p1,
		NewNextPublicKey: p2, CutWitnesses: []string{witnessKey}})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(rot.RawBytesB64)
	return raw, sign(t, c.signers[1], raw)
}

// craftedRotation is a rotation anybody could write from public facts: the
// right prefix, the right sequence number, the witness in its cut list, and no
// signature from anyone.
func (c *rotatingController) craftedRotation(t *testing.T, witnessKey string) []byte {
	t.Helper()
	p1, _ := c.signers[1].PublicKey()
	p2, _ := c.signers[2].PublicKey()
	nd, err := keri.NextDigest(p2)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := keri.BuildRotation(keri.RotationInput{Prefix: c.aid, Keys: []string{p1}, PriorSAID: c.icpSAID,
		SN: 1, NextDigests: []string{nd}, PriorWitnesses: []string{witnessKey}, Cuts: []string{witnessKey}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (p *peerAgent) takes(t *testing.T, aid string, raw []byte, sig string) error {
	t.Helper()
	_, err := p.svc.SubmitToWitness(context.Background(), p.base+"/api/witness/event", aid, raw, sig)
	return err
}

// takesAt delivers an event to the witness at the given address, the way a
// peer's BroadcastEvent does.
func (p *peerAgent) takesAt(t *testing.T, base, aid string, raw []byte, sig string) error {
	t.Helper()
	_, err := p.svc.SubmitToWitness(context.Background(), base+"/api/witness/event", aid, raw, sig)
	return err
}

// confirm posts a confirmation to the witness's real route and says whether it
// was accepted.
func (p *peerAgent) confirm(t *testing.T, aid string, rotation []byte) int {
	t.Helper()
	body, _ := json.Marshal(witness.WithdrawalConfirmation{ControllerAID: aid, WitnessKey: p.witnessKey,
		RotationRawB64: base64.StdEncoding.EncodeToString(rotation), ConfirmedAt: witness.NowRFC3339()})
	resp, err := http.Post(p.base+"/api/witness/withdraw/confirm", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func (p *peerAgent) stillWitnessing(t *testing.T, aid string) bool {
	t.Helper()
	m, _ := p.svc.Store.GetContactMeta(aid)
	return m != nil && m.WitnessingFor
}

// witnessedController is a witness that has taken a controller's inception.
func witnessedController(t *testing.T) (*peerAgent, *rotatingController) {
	t.Helper()
	bob := startPeer(t, "bob")
	c := newRotatingController(t, "subject", bob.witnessKey)
	bob.willWitnessFor(t, c.aid)
	if err := bob.takes(t, c.aid, c.icpRaw, c.icpSig); err != nil {
		t.Fatalf("bob would not witness the inception: %v", err)
	}
	return bob, c
}

// Each refusal is its own test, so that each can be shown to fail against the
// old check separately rather than only as part of one long flow.

func TestAnUnsignedRotationNamingTheWitnessDoesNotMakeItStandDown(t *testing.T) {
	bob, c := witnessedController(t)
	crafted := c.craftedRotation(t, bob.witnessKey) // anyone could write this
	if code := bob.confirm(t, c.aid, crafted); code == http.StatusOK {
		t.Fatal("an unsigned rotation naming the witness made it stand down")
	}
	if !bob.stillWitnessing(t, c.aid) {
		t.Fatal("the witness stopped on an unsigned rotation")
	}
}

func TestARotationSignedBySomebodyElseDoesNotMakeTheWitnessStandDown(t *testing.T) {
	bob, c := witnessedController(t)
	crafted := c.craftedRotation(t, bob.witnessKey)
	// The witness will not take it into the log, so it is not there to be
	// pointed at.
	stranger, _ := keri.GenerateSigner(true)
	if err := bob.takes(t, c.aid, crafted, sign(t, stranger, crafted)); err == nil {
		t.Fatal("the witness took a rotation signed by a stranger")
	}
	if code := bob.confirm(t, c.aid, crafted); code == http.StatusOK {
		t.Fatal("a rotation signed by somebody else made the witness stand down")
	}
	if !bob.stillWitnessing(t, c.aid) {
		t.Fatal("the witness stopped on a stranger's rotation")
	}
}

// A genuine rotation of another identity that bob also witnesses for. It is
// real, signed and in a log bob holds — but it is not this controller's.
func TestAnotherIdentitysRotationDoesNotMakeTheWitnessStandDownForThisOne(t *testing.T) {
	bob, c := witnessedController(t)
	other := newRotatingController(t, "other", bob.witnessKey)
	bob.willWitnessFor(t, other.aid)
	if err := bob.takes(t, other.aid, other.icpRaw, other.icpSig); err != nil {
		t.Fatal(err)
	}
	otherRot, otherSig := other.rotateCutting(t, bob.witnessKey)
	if err := bob.takes(t, other.aid, otherRot, otherSig); err != nil {
		t.Fatalf("bob would not take the other identity's rotation: %v", err)
	}
	if code := bob.confirm(t, c.aid, otherRot); code == http.StatusOK {
		t.Fatal("another identity's rotation made the witness stand down for this one")
	}
	if !bob.stillWitnessing(t, c.aid) {
		t.Fatal("the witness stopped for a controller that never rotated")
	}
}

// The real thing: signed by the key the inception committed to, in the log.
func TestTheControllersOwnSignedRotationMakesTheWitnessStandDown(t *testing.T) {
	bob, c := witnessedController(t)
	other := newRotatingController(t, "other", bob.witnessKey)
	bob.willWitnessFor(t, other.aid)
	if err := bob.takes(t, other.aid, other.icpRaw, other.icpSig); err != nil {
		t.Fatal(err)
	}
	rot, sig := c.rotateCutting(t, bob.witnessKey)
	if err := bob.takes(t, c.aid, rot, sig); err != nil {
		t.Fatalf("bob would not take the controller's real rotation: %v", err)
	}
	if code := bob.confirm(t, c.aid, rot); code != http.StatusOK {
		t.Fatalf("the controller's own signed rotation was refused (%d)", code)
	}
	if bob.stillWitnessing(t, c.aid) {
		t.Fatal("the witness is still witnessing after an accepted confirmation")
	}
	// Standing down for one identity leaves the other alone.
	if !bob.stillWitnessing(t, other.aid) {
		t.Fatal("standing down for one controller stopped the witness for another")
	}
}

// The whole exchange between two real agents, over the routes they serve: the
// witness asks to stop, the controller's agent rotates and tells it, and the
// witness checks the rotation against the log it holds.
func TestWithdrawalCompletesBetweenTwoAgentsOverTheirRoutes(t *testing.T) {
	withdrawalBetweenTwoAgents(t, func(p *peerAgent) string { return p.base })
}

// withdrawalBetweenTwoAgents runs the exchange with each agent reached at the
// address reach gives. Handed the bare witness routes it proves the protocol;
// handed the full router it proves a peer is let in to them (T-594).
func withdrawalBetweenTwoAgents(t *testing.T, reach func(*peerAgent) string) {
	bob := startPeer(t, "bob")     // the witness
	carol := startPeer(t, "carol") // the controller's agent
	bob.svc.OurAID = func() string { return "EBob" }

	c := newRotatingController(t, "subject", bob.witnessKey)
	bob.willWitnessFor(t, c.aid)
	if err := bob.takesAt(t, reach(bob), c.aid, c.icpRaw, c.icpSig); err != nil {
		t.Fatal(err)
	}
	// Each knows where the other is.
	if err := bob.svc.Contacts.SaveContact(store.ContactRecord{AID: c.aid, Status: "accepted",
		OobiURL: reach(carol) + "/public/oobi/" + c.aid}); err != nil {
		t.Fatal(err)
	}
	if err := carol.svc.Contacts.SaveContact(store.ContactRecord{AID: "EBob", Status: "accepted",
		OobiURL: reach(bob) + "/public/oobi/EBob"}); err != nil {
		t.Fatal(err)
	}
	if err := carol.svc.Store.SaveContactMeta(witness.ContactMeta{ContactAID: "EBob"}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := bob.svc.RequestWithdrawal(ctx, c.aid, witness.WithdrawalShuttingDown); err != nil {
		t.Fatalf("the controller's agent did not take the request: %v", err)
	}
	if !bob.stillWitnessing(t, c.aid) {
		t.Fatal("asking to stop stopped the witness")
	}

	rot, sig := c.rotateCutting(t, bob.witnessKey)
	// Not yet shown to the witness: the confirmation cannot be checked.
	conf := witness.WithdrawalConfirmation{ControllerAID: c.aid, WitnessKey: bob.witnessKey,
		RotationRawB64: base64.StdEncoding.EncodeToString(rot), ConfirmedAt: witness.NowRFC3339()}
	if err := carol.svc.ConfirmWithdrawal(ctx, "EBob", conf); err == nil {
		t.Fatal("the witness stood down on a rotation it had never been shown")
	}
	if err := bob.takesAt(t, reach(bob), c.aid, rot, sig); err != nil {
		t.Fatal(err)
	}
	if err := carol.svc.ConfirmWithdrawal(ctx, "EBob", conf); err != nil {
		t.Fatalf("the witness refused the controller's real rotation: %v", err)
	}
	if bob.stillWitnessing(t, c.aid) {
		t.Fatal("the withdrawal did not complete")
	}
}
