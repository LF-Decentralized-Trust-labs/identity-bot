package witness

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/iacrypto"
)

// A key state notice: how a witness says, live, how far it holds an
// identifier's key log.
//
// A receipt cannot say this. Every receipt a witness ever issued for an
// identifier stays valid for ever, so a log with its last rotation cut off is
// still a log whose every receipt checks out. What catches it is asking a
// witness NOW and believing the answer only if it can have come from nobody
// but that witness: the KERI reply /ksn/{aid}, signed by the witness's own
// non-transferable key and dated. An answer anybody could have typed (the
// key log served over plain HTTP) is not that, so it is not evidence.
//
// WHAT FRESH MEANS. KERI dates the reply and leaves the asker to decide how
// old is too old. This asker takes KeyStateFreshness: a notice older than that
// (or dated further ahead than that) is a replay, or a witness with the wrong
// clock, and is not believed.

// KeyStateFreshness is how far a notice's date may be from now.
const KeyStateFreshness = 5 * time.Minute

// KeyStateRoute is the reply route of a witness's key state notice for aid.
func KeyStateRoute(aid string) string { return "/ksn/" + aid }

// SignedReply is what a witness serves for a reply it makes about itself (a
// key state notice, a location): the reply as published, and the witness's
// signature over exactly those bytes.
type SignedReply struct {
	// RpyB64 is the reply message, base64 of its serialised bytes.
	RpyB64 string `json:"rpy_b64"`
	// WitnessAID is the key the answer says it was signed with. It is not
	// believed on its say-so: the asker holds the key it asked and checks the
	// signature against that.
	WitnessAID string `json:"witness_aid"`
	// Signature is the witness's unindexed Ed25519 signature (code 0B) over
	// the reply's bytes.
	Signature string `json:"signature"`
}

// KeyState is what a verified notice states.
type KeyState struct {
	AID string
	// SN is the place of the newest event the witness holds, -1 when it holds
	// none.
	SN int
	// SAID is that event's digest, empty when it holds none.
	SAID string
	// At is the date the witness gave the notice.
	At time.Time
}

type keyStateData struct {
	I string `json:"i"`
	S string `json:"s"`
	D string `json:"d"`
}

func replyDate(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000+00:00")
}

// BuildKeyStateNotice makes the reply for a witness holding the log of aid up
// to sn (-1 for none) whose newest event is said. The sequence number is
// written as KERI writes it, lowercase hex without leading zeros, and as
// nothing at all when no event is held.
func BuildKeyStateNotice(aid string, sn int, said string, at time.Time) ([]byte, error) {
	if aid == "" {
		return nil, fmt.Errorf("a key state notice names the identifier it is about")
	}
	d := keyStateData{I: aid, D: said}
	if sn >= 0 {
		d.S = strconv.FormatInt(int64(sn), 16)
	}
	data, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	return keri.BuildReply(keri.ReplyInput{Route: KeyStateRoute(aid), DT: replyDate(at), Data: data})
}

// VerifyKeyStateNotice reads a witness's answer about aid and believes it only
// if the reply is the message its own digest commits to, is the /ksn route for
// this identifier, states this identifier, is dated within KeyStateFreshness
// of now, and carries witnessKey's signature over its bytes. witnessKey is the
// key the asker is asking, from the log it is checking; never one the answer
// names.
func VerifyKeyStateNotice(ans SignedReply, witnessKey, aid string, now time.Time) (KeyState, error) {
	if _, err := iacrypto.KeyFromNonTransferableAID(witnessKey); err != nil {
		return KeyState{}, fmt.Errorf("%q is not a witness key: %w", witnessKey, err)
	}
	raw, err := base64.StdEncoding.DecodeString(ans.RpyB64)
	if err != nil || len(raw) == 0 || len(raw) > 4096 {
		return KeyState{}, fmt.Errorf("the key state notice is not readable")
	}
	sig, err := iacrypto.DecodeEd25519SignatureQB64(ans.Signature)
	if err != nil {
		return KeyState{}, fmt.Errorf("the key state notice carries no readable signature: %w", err)
	}
	if err := keri.VerifyUnderKey(witnessKey, raw, "", sig); err != nil {
		return KeyState{}, fmt.Errorf("the key state notice was not signed by the witness asked: %w", err)
	}
	rep, err := keri.VerifyReply(raw)
	if err != nil {
		return KeyState{}, err
	}
	if rep.Route != KeyStateRoute(aid) {
		return KeyState{}, fmt.Errorf("the notice is for %q, not %q", rep.Route, KeyStateRoute(aid))
	}
	at, err := time.Parse("2006-01-02T15:04:05.000000-07:00", rep.DT)
	if err != nil {
		return KeyState{}, fmt.Errorf("the notice's date %q is not one this reads", rep.DT)
	}
	if d := now.Sub(at); d > KeyStateFreshness || d < -KeyStateFreshness {
		return KeyState{}, fmt.Errorf("the notice is dated %s, which is not now", rep.DT)
	}
	var d keyStateData
	if err := json.Unmarshal(rep.Data, &d); err != nil || d.I != aid {
		return KeyState{}, fmt.Errorf("the notice is not about %s", aid)
	}
	out := KeyState{AID: aid, SN: -1, SAID: d.D, At: at}
	if d.S != "" {
		n, err := strconv.ParseInt(d.S, 16, 32)
		if err != nil || n < 0 || strconv.FormatInt(n, 16) != d.S {
			return KeyState{}, fmt.Errorf("the notice's sequence number %q is not written as KERI writes it", d.S)
		}
		out.SN = int(n)
	}
	if (out.SN < 0) != (out.SAID == "") {
		return KeyState{}, fmt.Errorf("the notice gives a place without an event, or an event without a place")
	}
	return out, nil
}

// KeyStateNotice is this witness's signed key state notice for aid. When the
// asker may not read the log (see MayRead) the notice is the one for a log that
// is not held, signed all the same, so the two cannot be told apart.
func (s *Service) KeyStateNotice(aid string, mayRead bool) (SignedReply, error) {
	if s.SignReceipt == nil {
		return SignedReply{}, fmt.Errorf("this agent has no witnessing key")
	}
	sn, said := -1, ""
	if mayRead {
		if kel, err := s.Store.GetKelEvents(aid); err == nil && len(kel) > 0 {
			last := kel[len(kel)-1]
			sn, said = last.SequenceNum, last.EventSAID
		}
	}
	raw, err := BuildKeyStateNotice(aid, sn, said, time.Now())
	if err != nil {
		return SignedReply{}, err
	}
	// The reply is JSON, so it is text, and a signature over its text is a
	// signature over its bytes.
	wit, sig, err := s.SignReceipt(string(raw))
	if err != nil {
		return SignedReply{}, err
	}
	return SignedReply{RpyB64: base64.StdEncoding.EncodeToString(raw), WitnessAID: wit, Signature: sig}, nil
}

// WitnessLocation is where a witness says it can be reached.
type WitnessLocation struct {
	URL string
}

// BuildWitnessLocation makes the /loc/scheme reply in which a witness states
// the address it is reached at, the message KERI uses for exactly that.
func BuildWitnessLocation(witnessAID, url string, at time.Time) ([]byte, error) {
	scheme := "https"
	if strings.HasPrefix(url, "http://") {
		scheme = "http"
	}
	return keri.EndpointLocation(witnessAID, scheme, url, replyDate(at))
}

// VerifyWitnessLocation reads a witness's signed statement of where it is
// reached, and believes it only if it is the /loc/scheme reply for witnessKey
// itself, signed by witnessKey over its bytes, naming an http or https
// address. A server at an address nobody vouches for cannot produce one: it
// does not hold the key.
//
// The date is not held to the freshness a key state notice is: a location is
// a standing statement, and a newer one supersedes it. Whether to believe
// what is at the address is decided by what the address then says, signed
// (VerifyKeyStateNotice), not by this.
func VerifyWitnessLocation(ans SignedReply, witnessKey string) (WitnessLocation, error) {
	if _, err := iacrypto.KeyFromNonTransferableAID(witnessKey); err != nil {
		return WitnessLocation{}, fmt.Errorf("%q is not a witness key: %w", witnessKey, err)
	}
	raw, err := base64.StdEncoding.DecodeString(ans.RpyB64)
	if err != nil || len(raw) == 0 || len(raw) > 4096 {
		return WitnessLocation{}, fmt.Errorf("the location is not readable")
	}
	sig, err := iacrypto.DecodeEd25519SignatureQB64(ans.Signature)
	if err != nil {
		return WitnessLocation{}, fmt.Errorf("the location carries no readable signature: %w", err)
	}
	if err := keri.VerifyUnderKey(witnessKey, raw, "", sig); err != nil {
		return WitnessLocation{}, fmt.Errorf("the location was not signed by the witness: %w", err)
	}
	rep, err := keri.VerifyReply(raw)
	if err != nil {
		return WitnessLocation{}, err
	}
	if rep.Route != keri.RouteLocationScheme {
		return WitnessLocation{}, fmt.Errorf("this is %q, not a location", rep.Route)
	}
	var d struct {
		EID    string `json:"eid"`
		Scheme string `json:"scheme"`
		URL    string `json:"url"`
	}
	if err := json.Unmarshal(rep.Data, &d); err != nil || d.EID != witnessKey {
		return WitnessLocation{}, fmt.Errorf("the location is not this witness's own")
	}
	if !strings.HasPrefix(d.URL, d.Scheme+"://") || (d.Scheme != "https" && d.Scheme != "http") {
		return WitnessLocation{}, fmt.Errorf("the location %q is not an address this will ask", d.URL)
	}
	return WitnessLocation{URL: strings.TrimRight(d.URL, "/")}, nil
}

// WitnessLocationNotice is this witness's signed statement of where it is
// reached, at url.
func (s *Service) WitnessLocationNotice(url string) (SignedReply, error) {
	if s.SignReceipt == nil || s.OurWitnessAID == nil {
		return SignedReply{}, fmt.Errorf("this agent has no witnessing key")
	}
	aid, err := s.OurWitnessAID()
	if err != nil {
		return SignedReply{}, err
	}
	raw, err := BuildWitnessLocation(aid, url, time.Now())
	if err != nil {
		return SignedReply{}, err
	}
	wit, sig, err := s.SignReceipt(string(raw))
	if err != nil {
		return SignedReply{}, err
	}
	return SignedReply{RpyB64: base64.StdEncoding.EncodeToString(raw), WitnessAID: wit, Signature: sig}, nil
}
