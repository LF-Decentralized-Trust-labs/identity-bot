package ownership

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/drivers"
	"identity-agent-core/drivers/signedlog"
	"identity-agent-core/internal/contractcheck"
)

// The published cases, built with the real engine: every event is made by
// keri-go and signed by the key KERI says must sign it, from seeds the file
// publishes, so anybody can make the same bytes. What each case expects is
// written here by hand and never taken from Check, which is then held to it.

const vectorsPath = "owned-vectors.json"

// maker builds the logs of the cases and remembers the seeds it used.
type maker struct {
	t         *testing.T
	seeds     map[string]string
	witnesses map[string]VectorWitness
}

func newMaker(t *testing.T) *maker {
	return &maker{t: t, seeds: map[string]string{}, witnesses: map[string]VectorWitness{}}
}

// seedOf is the published seed for a label: SHA-256 of "owned-vectors/" and
// the label. The derivation is only how the file was filled in; a reader
// takes the seed from the file.
func seedOf(label string) []byte {
	sum := sha256.Sum256([]byte("owned-vectors/" + label))
	return sum[:]
}

// keys are n keys for the identity called name, key i from the seed name/i.
func (m *maker) keys(name string, n int) *signedlog.Keys {
	var seeds [][]byte
	for i := 0; i < n; i++ {
		label := name + "/" + string(rune('0'+i))
		seeds = append(seeds, seedOf(label))
		m.seeds[label] = hex.EncodeToString(seedOf(label))
	}
	return signedlog.KeysFromSeeds(m.t, seeds...)
}

// witness is the witness called name.
func (m *maker) witness(name string) VectorWitness {
	seed := seedOf("witness/" + name)
	aid, err := keri.MatterQB64(keri.CodeEd25519N, ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	if err != nil {
		m.t.Fatal(err)
	}
	w := VectorWitness{Seed: hex.EncodeToString(seed), Identifier: aid}
	m.witnesses[name] = w
	return w
}

// witnessedBy is an inception that names one witness with a threshold of one.
func witnessedBy(w VectorWitness, seals ...json.RawMessage) keri.InceptionInput {
	one := 1
	return keri.InceptionInput{Witnesses: []string{w.Identifier}, Toad: &one, Data: seals}
}

func (m *maker) seal(identifier string, sn uint64, said string) json.RawMessage {
	s, err := EventSeal(identifier, sn, said)
	if err != nil {
		m.t.Fatal(err)
	}
	return s
}

// names is the owner seal naming owner: KERI's event seal of its inception.
func (m *maker) names(owner *signedlog.Log) json.RawMessage {
	return m.seal(owner.AID, 0, owner.AID)
}

// anchors is the anchor seal of event i of the Identity Agent's log.
func (m *maker) anchors(machine *signedlog.Log, i int) json.RawMessage {
	s, err := AnchorSeal(machine.Raws[i])
	if err != nil {
		m.t.Fatal(err)
	}
	return s
}

// receipt is w's receipt of event i of l.
func (m *maker) receipt(w VectorWitness, l *signedlog.Log, i int) map[string][]VectorReceipt {
	seed, _ := hex.DecodeString(w.Seed)
	sig, err := drivers.SignEventReceipt(l.Raws[i], seed, 0)
	if err != nil {
		m.t.Fatal(err)
	}
	return map[string][]VectorReceipt{l.SAID(i): {{Witness: w.Identifier, Signature: sig}}}
}

// handed is a copy of a log the party being checked handed over.
func handed(l *signedlog.Log, kept ...*signedlog.Log) VectorLog {
	v := VectorLog{Source: sourceCheckedParty, Messages: strings(l.Messages())}
	for _, k := range kept {
		v.Kept = append(v.Kept, strings(k.Messages()))
	}
	return v
}

// fetched is a copy of a log taken from its own witnesses, with receipts.
func fetched(l *signedlog.Log, receipts map[string][]VectorReceipt) VectorLog {
	return VectorLog{Source: sourceWitnesses, Messages: strings(l.Messages()), Receipts: receipts}
}

func strings(in [][]byte) []string {
	out := make([]string, 0, len(in))
	for _, b := range in {
		out = append(out, string(b))
	}
	return out
}

func expect(g Grade, why Reason, machine, owner *signedlog.Log) Result {
	return Result{Grade: g, Reason: why, Machine: machine.AID, Owner: owner.AID}
}

// at adds the event the owner entered at, and the interaction that anchors it.
func at(r Result, machine *signedlog.Log, e int, owner *signedlog.Log, anchoredBy int) Result {
	r.Event, r.EventSN = machine.SAID(e), uint64(e)
	if anchoredBy >= 0 {
		r.AnchoredBy = owner.SAID(anchoredBy)
	}
	return r
}

func makeVectors(t *testing.T) *VectorSet {
	m := newMaker(t)
	wm, wx := m.witness("of-the-machine"), m.witness("of-the-owner")

	// The pair most cases start from. The owner identity X names a witness;
	// the Identity Agent M names X in its inception and names a witness too;
	// X seals M's inception in an interaction event.
	founded := func() (machine, owner *signedlog.Log) {
		owner = signedlog.InceptWith(t, m.keys("owner", 3), witnessedBy(wx))
		machine = signedlog.InceptWith(t, m.keys("machine", 4), witnessedBy(wm, m.names(owner)))
		return machine, owner
	}
	machine, bare := founded()
	owner := bare.Fork().Seal(m.anchors(machine, 0))

	set := &VectorSet{
		About: "Whether an owner identity owns an Identity Agent, decided from their two key logs (ADR-087). " +
			"Each case gives the Identity Agent's log, the owner's log, where the verifier took each copy from, " +
			"any other copy or log it holds, and the grade and reason code the check must give. " +
			"The rules are in contracts/owned/owned.md. Every key comes from a seed published here.",
	}
	add := func(label, why string, mv, ov VectorLog, want Result, others ...VectorLog) {
		set.Cases = append(set.Cases, VectorCase{Label: label, Why: why, Machine: mv, Owner: ov, OtherLogs: others, Expect: want})
	}

	add("owned-and-anchored",
		"The owner's log seals the Identity Agent's inception in an interaction event. Both copies came from the party being checked, so the proof is anchored and no more.",
		handed(machine), handed(owner),
		at(expect(OwnedAnchored, NotFromWitnesses, machine, owner), machine, 0, owner, 1))

	add("owned-and-confirmed",
		"The same two logs, each taken from its own witnesses, with the inception and the anchoring interaction receipted to the threshold each log names.",
		fetched(machine, m.receipt(wm, machine, 0)), fetched(owner, m.receipt(wx, owner, 1)),
		at(expect(OwnedConfirmed, ReasonNone, machine, owner), machine, 0, owner, 1))

	add("confirmed-is-never-reported-for-a-copy-the-checked-party-handed-over",
		"Every receipt is present and the Identity Agent's log came from its witnesses, but the owner's log was handed over by the party being checked, which can hide a later event.",
		fetched(machine, m.receipt(wm, machine, 0)),
		VectorLog{Source: sourceCheckedParty, Messages: strings(owner.Messages()), Receipts: m.receipt(wx, owner, 1)},
		at(expect(OwnedAnchored, NotFromWitnesses, machine, owner), machine, 0, owner, 1))

	add("anchoring-event-not-receipted",
		"Both logs came from their witnesses, but the anchoring interaction carries no receipt, so the owner's witness is not shown to have seen it.",
		fetched(machine, m.receipt(wm, machine, 0)), fetched(owner, nil),
		at(expect(OwnedAnchored, ReceiptsShort, machine, owner), machine, 0, owner, 1))

	lookAlike := signedlog.InceptWith(t, m.keys("look-alike", 2), witnessedBy(wm, m.names(owner)))
	add("look-alike-names-the-owner",
		"Somebody else founded an Identity Agent whose inception names the same owner identity. Its log verifies and names the owner, and the owner's log seals a different inception: named, not owned.",
		handed(lookAlike), handed(owner),
		at(expect(NamedNotOwned, NamedNotAnchored, lookAlike, owner), lookAlike, 0, owner, -1))

	delegate := signedlog.InceptDelegated(t, m.keys("delegate", 2), bare.AID)
	approving := bare.Fork().Seal(m.seal(delegate.AID, 0, delegate.AID))
	add("delegation-approval-offered-as-an-anchor",
		"The owner's interaction seals the inception of an identity it delegated: the same seal shape as an anchor. What is sealed is a delegated inception, which is never owned.",
		handed(delegate), handed(approving),
		expect(Refused, Delegated, delegate, approving))

	delegatedNaming := signedlog.InceptDelegated(t, m.keys("delegate-naming", 2), bare.AID, m.names(bare))
	sealingIt := bare.Fork().Seal(m.seal(delegatedNaming.AID, 0, delegatedNaming.AID))
	add("machine-log-begins-with-a-delegated-inception",
		"The log begins with a delegated inception that also carries an owner seal naming the owner, and the owner's log seals it. It is named, and a log that begins with a delegated inception can never be owned.",
		handed(delegatedNaming), handed(sealingIt),
		expect(NamedNotOwned, Delegated, delegatedNaming, sealingIt))

	inEstablishment := bare.Fork().RotateSealing(m.anchors(machine, 0))
	add("anchor-in-an-establishment-event",
		"The seal of the Identity Agent's inception is in a rotation of the owner identity. An anchor is read only from an interaction event, because an event seal in an establishment event is that identity's own owner seal.",
		handed(machine), handed(inEstablishment),
		at(expect(NamedNotOwned, NamedNotAnchored, machine, inEstablishment), machine, 0, inEstablishment, -1))

	recovered := bare.Fork().Rotate() // a recovery rotation at the place the anchor held
	add("old-copy-hides-a-removal",
		"The owner identity has since replaced the anchoring interaction by a recovery rotation, and the party being checked hands over the old copy. It still verifies, so it proves anchored and can prove no more: only the owner's witnesses can show the removal.",
		handed(machine), handed(owner),
		at(expect(OwnedAnchored, NotFromWitnesses, machine, owner), machine, 0, owner, 1))
	add("old-copy-against-a-copy-the-verifier-kept",
		"The same old copy, shown to a verifier that already holds the owner's log with the recovery rotation in it. The copy does not carry on from the one kept, so it is refused.",
		handed(machine), handed(owner, recovered),
		at(expect(Refused, StaleCopy, machine, owner), machine, 0, owner, -1))

	add("anchor-removed-by-a-recovery-rotation",
		"The owner's log now holds a recovery rotation where the anchoring interaction was, and the verifier kept the earlier copy, so it can say the anchor was removed and has not been made again.",
		handed(machine), handed(recovered, owner),
		at(expect(NamedNotOwned, AnchorRemoved, machine, recovered), machine, 0, recovered, -1))
	reanchored := recovered.Fork().Seal(m.anchors(machine, 0))
	add("anchored-again-after-a-recovery",
		"After the recovery rotation the owner anchors the same inception in a new interaction event, which stands.",
		handed(machine), handed(reanchored, owner),
		at(expect(OwnedAnchored, NotFromWitnesses, machine, reanchored), machine, 0, reanchored, 2))

	// An owner that left and came back: the Identity Agent names X at its
	// inception, another owner alone at its first rotation, and X again at
	// its second.
	another := signedlog.Incept(t, m.keys("another-owner", 2))
	returning := machine.Fork().RotateSealing(m.names(another)).RotateSealing(m.names(owner), m.names(another))
	add("owner-left-and-came-back",
		"The owner was named at the inception, left out by the first rotation and named again by the second. Its anchor of the inception no longer counts: it is owned only from the event where it came back, which nothing anchors yet.",
		handed(returning), handed(owner),
		at(expect(NamedNotOwned, NamedNotAnchored, returning, owner), returning, 2, owner, -1))
	cameBack := owner.Fork().Seal(m.anchors(returning, 2))
	add("owner-came-back-and-anchored-the-event",
		"The same Identity Agent, once the owner has anchored the rotation in which it came back.",
		handed(returning), handed(cameBack),
		at(expect(OwnedAnchored, NotFromWitnesses, returning, cameBack), returning, 2, cameBack, 2))
	left := machine.Fork().RotateSealing(m.names(another))
	add("owner-left",
		"A later rotation of the Identity Agent names another owner alone. The old anchor stays in the owner's log and means only that it agreed at that event.",
		handed(left), handed(owner),
		expect(Refused, NotNamed, left, owner))

	second := signedlog.InceptWith(t, m.keys("second-machine", 2), witnessedBy(wm, m.names(owner)))
	both := owner.Fork().Seal(m.anchors(second, 0))
	add("second-machine-anchored-in-one-owner-log",
		"The owner's log anchors one Identity Agent and later a second. The first anchored is the only one this owner identity can own: the second is named, not owned.",
		handed(second), handed(both),
		at(expect(NamedNotOwned, SecondMachine, second, both), second, 0, both, -1),
		handed(machine))
	add("first-machine-in-an-owner-log-that-anchors-two",
		"The same owner log, checked for the Identity Agent it anchored first, which it still owns.",
		handed(machine), handed(both),
		at(expect(OwnedAnchored, NotFromWitnesses, machine, both), machine, 0, both, 1))
	add("seal-names-an-identifier-whose-log-was-not-supplied",
		"Before the anchor, the owner's log seals an event of another identifier, and the verifier was not given that identifier's log. Whether that was an earlier anchor cannot be told, so the result is that the log could not be checked.",
		handed(second), handed(both),
		at(expect(Refused, LogUnchecked, second, both), second, 0, both, -1))

	fork := bare.Fork().Interact("a second history")
	add("duplicitous-owner-log",
		"The verifier holds a second, validly signed interaction event at the place of the anchoring one. Two events at one place that no recovery explains are duplicity, and no Identity Agent is owned by such an owner.",
		handed(machine), handed(owner, fork),
		at(expect(Refused, Duplicity, machine, owner), machine, 0, owner, -1))

	set.Seeds, set.Witnesses = m.seeds, m.witnesses
	return set
}

func TestThePublishedVectorsAreWhatTheCodeMakesAndEveryOneIsJudgedAsItSays(t *testing.T) {
	made, err := json.MarshalIndent(makeVectors(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	made = append(made, '\n')
	if contractcheck.Writing(t) {
		if err := os.WriteFile(vectorsPath, made, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Skip("owned-vectors.json written; run again without IA_WRITE_CONTRACTS to check it")
	}
	onDisk, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(made, onDisk) {
		t.Fatal("owned-vectors.json is not what the code makes; if the format changed on purpose, run with IA_WRITE_CONTRACTS=1 and review the diff")
	}
	if !bytes.Equal(vectors, onDisk) {
		t.Fatal("the embedded vectors are not the file's")
	}

	set, err := Vectors()
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Cases) == 0 {
		t.Fatal("no cases are published")
	}
	for _, c := range set.Cases {
		got := c.Check()
		got.Detail = ""
		if got != c.Expect {
			t.Errorf("%s:\n  got  %+v\n  want %+v", c.Label, got, c.Expect)
		}
	}
}

// Every grade and every reason code is shown by at least one published case,
// so a code cannot be added to the check without a worked example of it.
func TestEveryReasonCodeHasAPublishedCase(t *testing.T) {
	set, err := Vectors()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[Reason]bool{}
	for _, c := range set.Cases {
		seen[c.Expect.Reason] = true
	}
	// LogInvalid is shown by the tests of a tampered log, not by a published
	// case: a file of logs that do not verify teaches a reader nothing more.
	for _, why := range []Reason{ReasonNone, NotFromWitnesses, ReceiptsShort, Delegated, NamedNotAnchored,
		AnchorRemoved, SecondMachine, NotNamed, StaleCopy, LogUnchecked, Duplicity} {
		if !seen[why] {
			t.Errorf("no published case shows the reason %q", why)
		}
	}
}

// An implementation written from contracts/owned/owned.md, in another
// language, agrees with the vector file.
func TestAnIndependentImplementationAgreesWithTheOwnedVectors(t *testing.T) {
	contractcheck.IndependentlyWith(t, "../contracts/check_owned_vectors.py", vectorsPath, "blake3")
}
