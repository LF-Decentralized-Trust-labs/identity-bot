package witnessproto

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	keri "github.com/grapeid/keri-go"
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

// maxLocationBytes bounds a witness location: one identifier and one address.
const maxLocationBytes = 4096

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

// ReplyDate is how KERI dates a reply (keripy's nowIso8601): UTC, to the
// microsecond, with the offset written out.
func ReplyDate(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000+00:00")
}

// decodeBounded is the base64 reply b64, refused unread when it would decode to
// more than max bytes.
func decodeBounded(b64 string, max int) ([]byte, bool) {
	if len(b64) > base64.StdEncoding.EncodedLen(max) {
		return nil, false
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) == 0 || len(raw) > max {
		return nil, false
	}
	return raw, true
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
	return keri.BuildReply(keri.ReplyInput{Route: KeyStateRoute(witnessAID), DT: ReplyDate(at), Data: data})
}

// NoKeyState is the record of an identifier nothing is held for.
func NoKeyState(aid string) KeyStateRecord {
	return KeyStateRecord{VN: []int{1, 0}, I: aid, K: []string{}, N: []string{}, B: []string{}, C: []string{},
		EE: keyStateEstEvent{BR: []string{}, BA: []string{}}}
}

// LoggedEvent is one event of a key log as a witness holds it: the bytes the
// controller published (base64), where it stands, and when it was stored.
type LoggedEvent struct {
	SequenceNum int
	RawBytesB64 string
	StoredAt    string
}

// KeyStateRecordOf is the key state after the newest event of a key log a
// witness holds, read from the events' own bytes (never from what the store
// says beside them), following br and ba for the witnesses in force.
//
// It checks the log is one chain (an inception first, each event at the next
// place, naming the one before it as its prior) but not its signatures: the
// witness checked those when it accepted each event, and states only what it
// holds. f, keripy's first-seen ordinal, is written equal to s: a witness here
// holds one event at each place, so the two differ only after a recovery
// rotation has superseded events, which this record does not follow.
func KeyStateRecordOf(aid string, kel []LoggedEvent) (KeyStateRecord, error) {
	rec := NoKeyState(aid)
	if len(kel) == 0 {
		return rec, nil
	}
	var held []string
	var prior string
	for i, row := range kel {
		raw, err := base64.StdEncoding.DecodeString(row.RawBytesB64)
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
		if i == 0 && ev.Ilk != "icp" && ev.Ilk != "dip" {
			return KeyStateRecord{}, fmt.Errorf("the log of %s does not start with its inception", aid)
		}
		if i > 0 && ev.PriorSAID != prior {
			return KeyStateRecord{}, fmt.Errorf("event %d does not name the event before it as its prior", row.SequenceNum)
		}
		stored, err := time.Parse(time.RFC3339Nano, row.StoredAt)
		if err != nil {
			return KeyStateRecord{}, fmt.Errorf("event %d is held with no readable date: %w", row.SequenceNum, err)
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
		held, _ = WitnessesAfter(held, ev)
		rec.P, rec.D, rec.ET = prior, ev.SAID, ev.Ilk
		rec.S = strconv.FormatUint(ev.SN, 16)
		rec.F = rec.S
		rec.DT = ReplyDate(stored)
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
	if _, err := keri.MatterRaw("B", witnessKey, 32); err != nil {
		return KeyState{}, fmt.Errorf("%q is not a witness key: %w", witnessKey, err)
	}
	raw, ok := decodeBounded(ans.RpyB64, maxNoticeBytes)
	if !ok {
		return KeyState{}, fmt.Errorf("the key state notice is not readable")
	}
	sig, err := keri.MatterRawSized("0B", ans.Signature, 64)
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

// WitnessLocation is where a witness says it can be reached.
type WitnessLocation struct {
	URL string
}

// BuildWitnessLocation makes the /loc/scheme reply in which a witness states
// the address it is reached at, the message KERI uses for exactly that. The
// address is http or https, the only schemes VerifyWitnessLocation believes,
// so an address of any other scheme is refused here rather than signed.
func BuildWitnessLocation(witnessAID, url string, at time.Time) ([]byte, error) {
	var scheme string
	switch {
	case strings.HasPrefix(url, "https://"):
		scheme = "https"
	case strings.HasPrefix(url, "http://"):
		scheme = "http"
	default:
		return nil, fmt.Errorf("the witness address %q is not an http or https address", url)
	}
	return keri.EndpointLocation(witnessAID, scheme, url, ReplyDate(at))
}

// VerifyWitnessLocation reads a witness's signed statement of where it is
// reached, and believes it only if it is the /loc/scheme reply for witnessKey
// itself, signed by witnessKey over its bytes, naming an http or https
// address with a host and nothing but a host, a port and a path (no user
// name or password, query or fragment). A server at an address nobody vouches for cannot produce one: it
// does not hold the key.
//
// The date is not held to the freshness a key state notice is: a location is
// a standing statement, and a newer one supersedes it. Whether to believe
// what is at the address is decided by what the address then says, signed
// (VerifyKeyStateNotice), not by this.
func VerifyWitnessLocation(ans SignedReply, witnessKey string) (WitnessLocation, error) {
	if _, err := keri.MatterRaw("B", witnessKey, 32); err != nil {
		return WitnessLocation{}, fmt.Errorf("%q is not a witness key: %w", witnessKey, err)
	}
	raw, ok := decodeBounded(ans.RpyB64, maxLocationBytes)
	if !ok {
		return WitnessLocation{}, fmt.Errorf("the location is not readable")
	}
	sig, err := keri.MatterRawSized("0B", ans.Signature, 64)
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
	// Read by hand rather than with net/url, so this module (which key
	// arithmetic imports) reaches nothing of the network.
	rest := d.URL[len(d.Scheme)+3:]
	host, _, _ := strings.Cut(rest, "/")
	if host == "" || strings.HasPrefix(host, ":") || strings.ContainsAny(rest, "@?# \t\r\n") {
		return WitnessLocation{}, fmt.Errorf("the location %q is not a plain address: it needs a host, and no user, query or fragment", d.URL)
	}
	return WitnessLocation{URL: strings.TrimRight(d.URL, "/")}, nil
}

// Signer signs text with the witness's own key and says which key it used: the
// witness's identifier and the unindexed Ed25519 signature (code 0B).
type Signer func(text string) (witnessAID, signature string, err error)

// SignReply signs a reply that the witness whose key is ours makes about itself. The reply is
// JSON, so it is text, and a signature over its text is a signature over its
// bytes. It is refused if the key that signed is not the witness the reply
// names.
func SignReply(raw []byte, ours string, sign Signer) (SignedReply, error) {
	wit, sig, err := sign(string(raw))
	if err != nil {
		return SignedReply{}, err
	}
	if wit != ours {
		return SignedReply{}, fmt.Errorf("the key signing is not the witness key the reply names")
	}
	return SignedReply{RpyB64: base64.StdEncoding.EncodeToString(raw), WitnessAID: wit, Signature: sig}, nil
}

// SignedKeyStateNotice is the key state notice in which the witness whose key is
// ours states rec, signed.
func SignedKeyStateNotice(ours string, rec KeyStateRecord, at time.Time, sign Signer) (SignedReply, error) {
	raw, err := BuildKeyStateNotice(ours, rec, at)
	if err != nil {
		return SignedReply{}, err
	}
	return SignReply(raw, ours, sign)
}

// SignedWitnessLocation is the statement, signed, that the witness whose key is
// ours is reached at url.
func SignedWitnessLocation(ours, url string, at time.Time, sign Signer) (SignedReply, error) {
	raw, err := BuildWitnessLocation(ours, url, at)
	if err != nil {
		return SignedReply{}, err
	}
	return SignReply(raw, ours, sign)
}
