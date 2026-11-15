package witness

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
)

// A key state notice: how a witness says, live, how far it holds an
// identifier's key log.
//
// A receipt cannot say this. Every receipt a witness ever issued for an
// identifier stays valid for ever, so a log with its last rotation cut off is
// still a log whose every receipt checks out. What catches it is asking a
// witness NOW and believing the answer only if it can have come from nobody
// but that witness: the KERI reply /ksn/{witness}, signed by the witness's own
// non-transferable key and dated. An answer anybody could have typed (the
// key log served over plain HTTP) is not that, so it is not evidence.
//
// WHAT FRESH MEANS. KERI dates the reply and leaves the asker to decide how
// old is too old. This asker takes KeyStateFreshness: a notice older than that
// (or dated further ahead than that) is a replay, or a witness with the wrong
// clock, and is not believed.

// maxNoticeBytes bounds a key state notice. It carries the whole key state, whose
// keys, next-key digests and witnesses each take 44 characters, so an identity
// with many of them has a long one.
const maxNoticeBytes = 64 * 1024

// KeyStateFreshness is how far a notice's date may be from now.
const KeyStateFreshness = 5 * time.Minute

// KeyStateRoute is the reply route of a key state notice given by the witness
// whose key is witnessAID. KERI names the witness that signs the notice, not
// the identifier the notice is about: keripy's reply is /ksn/{witness} and the
// identifier is in the state the reply carries.
func KeyStateRoute(witnessAID string) string { return "/ksn/" + witnessAID }

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

// KeyStateRecord is keripy's key state record: the whole state of an
// identifier's log after its newest event, which is what the `a` of a /ksn reply
// carries. Field names and order are keripy's.
type KeyStateRecord struct {
	VN []int  `json:"vn"`
	I  string `json:"i"`
	S  string `json:"s"`
	P  string `json:"p"`
	D  string `json:"d"`
	F  string `json:"f"`
	DT string `json:"dt"`
	ET string `json:"et"`
	// KT and NT are the signing and next thresholds as the establishment event
	// wrote them (a hex string, or a list for a weighted one).
	KT interface{}      `json:"kt"`
	K  []string         `json:"k"`
	NT interface{}      `json:"nt"`
	N  []string         `json:"n"`
	BT string           `json:"bt"`
	B  []string         `json:"b"`
	C  []string         `json:"c"`
	EE keyStateEstEvent `json:"ee"`
	DI string           `json:"di"`
}

// keyStateEstEvent is the `ee` of a key state record: the last establishment
// event.
type keyStateEstEvent struct {
	S  string   `json:"s"`
	D  string   `json:"d"`
	BR []string `json:"br"`
	BA []string `json:"ba"`
}

func replyDate(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000+00:00")
}

// BuildKeyStateNotice makes the reply in which the witness whose key is
// witnessAID states the key state of an identifier: keripy's /ksn/{witness}
// carrying the full state record. A witness that holds nothing for the
// identifier states a record with only the identifier (nothing at s and d),
// where keripy would not answer; the asker has to be told apart from "no
// reply", and has to be unable to tell "not held" from "not allowed to read".
func BuildKeyStateNotice(witnessAID string, rec KeyStateRecord, at time.Time) ([]byte, error) {
	if witnessAID == "" || rec.I == "" {
		return nil, fmt.Errorf("a key state notice names the witness giving it and the identifier it is about")
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	return keri.BuildReply(keri.ReplyInput{Route: KeyStateRoute(witnessAID), DT: replyDate(at), Data: data})
}

// NoKeyState is the record of an identifier nothing is held for.
func NoKeyState(aid string) KeyStateRecord {
	return KeyStateRecord{VN: []int{1, 0}, I: aid, K: []string{}, N: []string{}, B: []string{}, C: []string{},
		EE: keyStateEstEvent{BR: []string{}, BA: []string{}}}
}

// KeyStateRecordOf is the key state after the newest event of a key log a
// witness holds, read from the events' own bytes (never from what the store
// says beside them), following br and ba for the witnesses in force.
func KeyStateRecordOf(aid string, kel []KelEvent) (KeyStateRecord, error) {
	rec := NoKeyState(aid)
	if len(kel) == 0 {
		return rec, nil
	}
	var held []string
	var prior string
	for i, row := range kel {
		raw, err := drivers.DecodeRawBytes(row.RawBytesB64)
		if err != nil || len(raw) == 0 {
			return KeyStateRecord{}, fmt.Errorf("event %d is held without its bytes, so the key state cannot be stated", row.SequenceNum)
		}
		ev, err := keri.ParseEvent(raw)
		if err != nil {
			return KeyStateRecord{}, fmt.Errorf("event %d is not readable: %w", row.SequenceNum, err)
		}
		if ev.Identifier != aid || ev.SN != uint64(i) {
			return KeyStateRecord{}, fmt.Errorf("event %d is not the next event of %s", row.SequenceNum, aid)
		}
		var f map[string]json.RawMessage
		if err := json.Unmarshal(raw, &f); err != nil {
			return KeyStateRecord{}, err
		}
		field := func(name string) interface{} {
			var v interface{}
			_ = json.Unmarshal(f[name], &v)
			return v
		}
		list := func(name string) []string {
			var v []string
			if json.Unmarshal(f[name], &v) != nil || v == nil {
				return []string{}
			}
			return v
		}
		held, _ = drivers.WitnessesAfter(held, ev)
		rec.P, rec.D, rec.ET = prior, ev.SAID, ev.Ilk
		rec.S = strconv.FormatUint(ev.SN, 16)
		rec.F = rec.S
		if t, err := time.Parse(time.RFC3339Nano, row.StoredAt); err == nil {
			rec.DT = replyDate(t)
		}
		if ev.Delegator != "" {
			rec.DI = ev.Delegator
		}
		if ev.Establishment() {
			rec.KT, rec.K, rec.NT, rec.N = field("kt"), ev.Keys, field("nt"), ev.NextDigest
			rec.BT = strconv.FormatUint(ev.TOAD, 16)
			if c := list("c"); len(c) > 0 || ev.Ilk == "icp" || ev.Ilk == "dip" {
				rec.C = c
			}
			rec.EE = keyStateEstEvent{S: rec.S, D: ev.SAID, BR: list("br"), BA: list("ba")}
		}
		rec.B = append([]string{}, held...)
		prior = ev.SAID
	}
	if rec.K == nil {
		rec.K = []string{}
	}
	if rec.N == nil {
		rec.N = []string{}
	}
	return rec, nil
}

// VerifyKeyStateNotice reads a witness's answer about aid and believes it only
// if the reply is the message its own digest commits to, is the /ksn route of
// witnessKey (keripy's, naming the witness giving it), states the key state of
// this identifier, is dated within KeyStateFreshness
// of now, and carries witnessKey's signature over its bytes. witnessKey is the
// key the asker is asking, from the log it is checking; never one the answer
// names.
func VerifyKeyStateNotice(ans SignedReply, witnessKey, aid string, now time.Time) (KeyState, error) {
	if _, err := iacrypto.KeyFromNonTransferableAID(witnessKey); err != nil {
		return KeyState{}, fmt.Errorf("%q is not a witness key: %w", witnessKey, err)
	}
	raw, err := base64.StdEncoding.DecodeString(ans.RpyB64)
	if err != nil || len(raw) == 0 || len(raw) > maxNoticeBytes {
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
	// The route names the witness giving the notice. Checking it is what keeps
	// a notice one witness gave from being replayed as another's.
	if rep.Route != KeyStateRoute(witnessKey) {
		return KeyState{}, fmt.Errorf("the notice is for %q, not %q", rep.Route, KeyStateRoute(witnessKey))
	}
	at, err := time.Parse("2006-01-02T15:04:05.000000-07:00", rep.DT)
	if err != nil {
		return KeyState{}, fmt.Errorf("the notice's date %q is not one this reads", rep.DT)
	}
	if d := now.Sub(at); d > KeyStateFreshness || d < -KeyStateFreshness {
		return KeyState{}, fmt.Errorf("the notice is dated %s, which is not now", rep.DT)
	}
	var d KeyStateRecord
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
	if s.SignReceipt == nil || s.OurWitnessAID == nil {
		return SignedReply{}, fmt.Errorf("this agent has no witnessing key")
	}
	ours, err := s.OurWitnessAID()
	if err != nil {
		return SignedReply{}, err
	}
	rec := NoKeyState(aid)
	if mayRead {
		if kel, err := s.Store.GetKelEvents(aid); err == nil && len(kel) > 0 {
			if rec, err = KeyStateRecordOf(aid, kel); err != nil {
				return SignedReply{}, err
			}
		}
	}
	raw, err := BuildKeyStateNotice(ours, rec, time.Now())
	if err != nil {
		return SignedReply{}, err
	}
	// The reply is JSON, so it is text, and a signature over its text is a
	// signature over its bytes.
	wit, sig, err := s.SignReceipt(string(raw))
	if err != nil {
		return SignedReply{}, err
	}
	if wit != ours {
		return SignedReply{}, fmt.Errorf("the key signing is not the witness key the notice names")
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
	if d.Scheme != "https" && d.Scheme != "http" {
		return WitnessLocation{}, fmt.Errorf("the location's scheme %q is not http or https, which are the only ones this asks", d.Scheme)
	}
	if !strings.HasPrefix(d.URL, d.Scheme+"://") {
		return WitnessLocation{}, fmt.Errorf("the location %q is not an address of its own scheme %q", d.URL, d.Scheme)
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
