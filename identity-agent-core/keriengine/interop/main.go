// Judge the KERI engine's output with keriox — an implementation written by
// other people from a reading of the same specification.
//
// The engine's own tests check it against the Go KERI library it is built on,
// which is a check that shares an origin with the thing being checked. This
// does not: keriox is independent Rust, and it either accepts these events or
// it does not.
//
// The engine holds no keys and cannot sign, so this harness signs each event
// the way the controller device would before publishing it.
//
//	go run ./keriengine/interop | cargo run --manifest-path \
//	  ../../keri-go/interop-keriox/Cargo.toml
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"identity-agent-core/keriengine"

	keri "github.com/grapeid/keri-go"
)

type kase struct {
	Label string `json:"label"`
	Kind  string `json:"kind"`
	Why   string `json:"why"`
	Event string `json:"event_b64,omitempty"`
	Msg   string `json:"message_b64,omitempty"`
}

var cases []kase

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "harness:", err)
		os.Exit(1)
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func decode(s string) []byte {
	raw, err := base64.StdEncoding.DecodeString(s)
	must(err)
	return raw
}

// emit signs an event the engine produced and records it for keriox.
func emit(label, why string, rawB64 string, signers ...keri.Signer) {
	event := decode(rawB64)
	signed, err := keri.SignEvent(event, signers...)
	must(err)
	cases = append(cases, kase{
		Label: label, Kind: "kel", Why: why,
		Event: b64(signed.Event), Msg: b64(signed.Message),
	})
}

func pub(s keri.Signer) string {
	p, err := s.PublicKey()
	must(err)
	return p
}

func main() {
	e := keriengine.New()

	// One identity taken through its whole life: founded, rotated to the key it
	// committed to, then used to anchor something. Each event is signed by the
	// key that event declares, which is what keriox checks.
	a, err := keri.GenerateSigner(true)
	must(err)
	b, err := keri.GenerateSigner(true)
	must(err)
	c, err := keri.GenerateSigner(true)
	must(err)

	icp, err := e.CreateInceptionNamed(pub(a), pub(b), "subject")
	must(err)
	emit("engine/icp", "an identity this engine founded", icp.RawBytesB64, a)

	rot, err := e.RotateAid("subject", pub(b), pub(c))
	must(err)
	// A rotation is signed by the key it reveals, not the one it supersedes.
	emit("engine/rot", "the engine rotated to the key it had committed to", rot.RawBytesB64, b)

	ixn, err := e.Interact("subject", []interface{}{map[string]string{"i": icp.AID, "s": "0", "d": icp.AID}})
	must(err)
	emit("engine/ixn", "an interaction anchoring data after a rotation", ixn.RawBytesB64, b)

	// Control: is it the seal, or is it anything at all after a rotation?
	// A second identity, interacting straight after inception with no rotation
	// in between, isolates the two.
	g, err := keri.GenerateSigner(true)
	must(err)
	h, err := keri.GenerateSigner(true)
	must(err)
	plain, err := e.CreateInceptionNamed(pub(g), pub(h), "plain")
	must(err)
	emit("control/icp", "a second identity, for the control", plain.RawBytesB64, g)
	// A plain Go map, deliberately: a map has no order, and the engine is
	// responsible for writing the seal in the specified one. This case fails if
	// it ever stops doing that.
	plainIxn, err := e.Interact("plain", []interface{}{
		map[string]string{"i": plain.AID, "s": "0", "d": plain.AID}})
	must(err)
	emit("control/ixn-no-rotation", "the same seal, but with no rotation before it", plainIxn.RawBytesB64, g)

	// An identity that records its owner in its own inception event.
	d, err := keri.GenerateSigner(true)
	must(err)
	f, err := keri.GenerateSigner(true)
	must(err)
	owned, err := e.CreateOwnedInception(pub(d), pub(f), "owned", icp.AID)
	must(err)
	emit("engine/icp-owned", "an inception carrying anchored owner data", owned.RawBytesB64, d)

	// The credential path anchors seals too — a registry inception, an issuance
	// and a revocation each extend the issuer's log. Those seals are built by
	// the engine itself rather than supplied by a caller, so a mistake in them
	// would show here and nowhere else.
	//
	// Only the issuance response reports its anchoring event as bytes, so the
	// other two are read back from the log, which is where they actually live.
	tail := func() string {
		kel, err := e.GetKel("plain")
		must(err)
		return kel.RawEventsB64[len(kel.RawEventsB64)-1]
	}

	reg, err := e.InceptRegistry("plain")
	must(err)
	_ = reg
	emit("engine/ixn-registry", "the interaction anchoring a registry", tail(), g)

	schema, err := keri.Blake3SAID([]byte("an interop schema"))
	must(err)
	issued, err := e.IssueCredentialInRegistry("plain",
		map[string]interface{}{"role": "engineer"}, schema, icp.AID, nil, reg.RegistrySaid)
	must(err)
	emit("engine/ixn-issuance", "the interaction anchoring a credential issuance",
		issued.IxnRawBytesB64, g)

	if _, err := e.RevokeCredential("plain", issued.AcdcSaid, reg.RegistrySaid, issued.IssSaid); err != nil {
		must(err)
	}
	emit("engine/ixn-revocation", "the interaction anchoring a revocation", tail(), g)

	out, err := json.Marshal(cases)
	must(err)
	fmt.Println(string(out))
}
