package witnessproto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	keri "github.com/grapeid/keri-go"
)

type testWitness struct {
	priv ed25519.PrivateKey
	aid  string
}

func newTestWitness(t *testing.T) testWitness {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aid, err := keri.MatterQB64("B", pub)
	if err != nil {
		t.Fatal(err)
	}
	return testWitness{priv: priv, aid: aid}
}

func (w testWitness) sign(text string) (string, string, error) {
	sig, err := keri.MatterQB64("0B", ed25519.Sign(w.priv, []byte(text)))
	return w.aid, sig, err
}

func logEvents(aid string, evs ...string) []LoggedEvent {
	var out []LoggedEvent
	for i, e := range evs {
		out = append(out, LoggedEvent{SequenceNum: i, RawBytesB64: base64.StdEncoding.EncodeToString([]byte(e)),
			StoredAt: "2026-11-13T10:00:00Z"})
	}
	return out
}

func icp(aid string, b ...string) string {
	bj, _ := json.Marshal(append([]string{}, b...))
	return fmt.Sprintf(`{"v":"KERI10JSON000000_","t":"icp","d":"E%s0","i":%q,"s":"0","kt":"1","k":["DKey"],"nt":"1","n":["ENext"],"bt":"1","b":%s,"c":[],"a":[]}`, aid[:6], aid, bj)
}

// A key state notice is the KERI reply /ksn/{signing witness}, carrying the
// whole key state record, and is believed only as that witness's own, live.
func TestAKeyStateNoticeIsBelievedOnlyAsTheAskedWitnesssOwnAndLive(t *testing.T) {
	w, other := newTestWitness(t), newTestWitness(t)
	aid := "EAbcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"
	now := time.Now()
	ans, err := SignedKeyStateNotice(w.aid, NoKeyState(aid), now, w.sign)
	if err != nil {
		t.Fatal(err)
	}
	st, err := VerifyKeyStateNotice(ans, w.aid, aid, now)
	if err != nil || st.SN != -1 || st.SAID != "" {
		t.Fatalf("a notice for nothing held = %+v, %v", st, err)
	}
	if raw, _ := base64.StdEncoding.DecodeString(ans.RpyB64); !strings.Contains(string(raw), `"r":"/ksn/`+w.aid+`"`) {
		t.Fatalf("the route must name the signing witness, as keripy's does: %s", raw)
	}
	for name, run := range map[string]func() error{
		"another witness's notice replayed as this one's": func() error { _, e := VerifyKeyStateNotice(ans, other.aid, aid, now); return e },
		"a notice about another identifier": func() error {
			_, e := VerifyKeyStateNotice(ans, w.aid, "EOther"+aid[6:], now)
			return e
		},
		"a stale notice": func() error {
			_, e := VerifyKeyStateNotice(ans, w.aid, aid, now.Add(KeyStateFreshness+time.Minute))
			return e
		},
		"a notice dated ahead": func() error {
			_, e := VerifyKeyStateNotice(ans, w.aid, aid, now.Add(-KeyStateFreshness-time.Minute))
			return e
		},
		"a signature by nobody asked": func() error {
			bad := ans
			bad.Signature = mustSig(t, other, ans.RpyB64)
			_, e := VerifyKeyStateNotice(bad, w.aid, aid, now)
			return e
		},
		"a key that is not a witness key": func() error { _, e := VerifyKeyStateNotice(ans, "Dnotawitnesskey", aid, now); return e },
	} {
		if run() == nil {
			t.Errorf("%s was believed", name)
		}
	}
}

func mustSig(t *testing.T, w testWitness, rpyB64 string) string {
	t.Helper()
	raw, _ := base64.StdEncoding.DecodeString(rpyB64)
	_, sig, err := w.sign(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// The record is read from the events' own bytes and follows br and ba.
func TestTheKeyStateRecordFollowsTheLogAndItsWitnesses(t *testing.T) {
	aid := "EAbcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"
	rec, err := KeyStateRecordOf(aid, nil)
	if err != nil || rec.S != "" || rec.D != "" || rec.I != aid {
		t.Fatalf("an empty log = %+v, %v", rec, err)
	}
	first := icp(aid, "BW1", "BW2")
	rot := fmt.Sprintf(`{"v":"KERI10JSON000000_","t":"rot","d":"EROT","i":%q,"s":"1","p":"E%s0","kt":"1","k":["DKey2"],"nt":"1","n":["ENext2"],"bt":"1","br":["BW1"],"ba":["BW3"],"a":[]}`, aid, aid[:6])
	rec, err = KeyStateRecordOf(aid, logEvents(aid, first, rot))
	if err != nil {
		t.Fatal(err)
	}
	if rec.S != "1" || rec.D != "EROT" || rec.ET != "rot" || rec.P != "E"+aid[:6]+"0" || rec.EE.D != "EROT" {
		t.Errorf("record = %+v", rec)
	}
	if strings.Join(rec.B, ",") != "BW2,BW3" || strings.Join(rec.K, ",") != "DKey2" {
		t.Errorf("witnesses in force %v, keys %v", rec.B, rec.K)
	}
	if strings.Join(rec.EE.BR, ",") != "BW1" || strings.Join(rec.EE.BA, ",") != "BW3" || rec.EE.S != "1" {
		t.Errorf("last establishment = %+v", rec.EE)
	}
	if rec.DT != "2026-11-13T10:00:00.000000+00:00" || rec.BT != "1" {
		t.Errorf("dt %q, bt %q", rec.DT, rec.BT)
	}

	// An interaction moves the place and the event, not the keys or witnesses.
	ixn := fmt.Sprintf(`{"v":"KERI10JSON000000_","t":"ixn","d":"EIXN","i":%q,"s":"2","p":"EROT","a":[]}`, aid)
	rec, err = KeyStateRecordOf(aid, logEvents(aid, first, rot, ixn))
	if err != nil {
		t.Fatal(err)
	}
	if rec.S != "2" || rec.D != "EIXN" || rec.ET != "ixn" || rec.P != "EROT" || rec.EE.D != "EROT" ||
		strings.Join(rec.K, ",") != "DKey2" || strings.Join(rec.N, ",") != "ENext2" || strings.Join(rec.B, ",") != "BW2,BW3" {
		t.Errorf("after an interaction, record = %+v", rec)
	}

	// Places and thresholds are written in hex, as KERI writes them.
	evs := []string{icp(aid, "BW1")}
	prior := "E" + aid[:6] + "0"
	for sn := 1; sn <= 11; sn++ {
		d := fmt.Sprintf("EIXN%d", sn)
		evs = append(evs, fmt.Sprintf(`{"v":"KERI10JSON000000_","t":"ixn","d":%q,"i":%q,"s":"%x","p":%q,"a":[]}`, d, aid, sn, prior))
		prior = d
	}
	if rec, err = KeyStateRecordOf(aid, logEvents(aid, evs...)); err != nil || rec.S != "b" || rec.F != "b" {
		t.Errorf("eleven events on = %+v, %v; want s b", rec, err)
	}
	big := strings.Replace(icp(aid, "BW1"), `"bt":"1"`, `"bt":"a"`, 1)
	if rec, err = KeyStateRecordOf(aid, logEvents(aid, big)); err != nil || rec.BT != "a" {
		t.Errorf("a threshold of ten = %q, %v; want a", rec.BT, err)
	}

	// A delegated identifier names its delegator.
	dip := fmt.Sprintf(`{"v":"KERI10JSON000000_","t":"dip","d":"EDIP","i":%q,"s":"0","kt":"1","k":["DKey"],"nt":"1","n":["ENext"],"bt":"0","b":[],"c":[],"a":[],"di":"EDelegator"}`, aid)
	if rec, err = KeyStateRecordOf(aid, logEvents(aid, dip)); err != nil || rec.DI != "EDelegator" || rec.ET != "dip" {
		t.Errorf("a delegated inception = %+v, %v", rec, err)
	}

	// What is not one chain of this identifier's events is refused, not stated.
	if _, err := KeyStateRecordOf(aid, logEvents(aid, rot)); err == nil {
		t.Error("a log that starts at a rotation was stated")
	}
	if _, err := KeyStateRecordOf(aid, logEvents(aid, strings.Replace(ixn, `"s":"2"`, `"s":"0"`, 1))); err == nil {
		t.Error("a log that starts at an interaction was stated")
	}
	if _, err := KeyStateRecordOf(aid, logEvents(aid, first, strings.Replace(rot, `"p":"E`+aid[:6]+`0"`, `"p":"EWRONG"`, 1))); err == nil {
		t.Error("an event naming another prior was stated")
	}
	if _, err := KeyStateRecordOf("EOther"+aid[6:], logEvents(aid, first)); err == nil {
		t.Error("another identifier's log was stated")
	}
	undated := logEvents(aid, first)
	undated[0].StoredAt = "2026-11-13 10:05:00"
	if _, err := KeyStateRecordOf(aid, undated); err == nil {
		t.Error("an event held with no readable date was stated")
	}
	if _, err := KeyStateRecordOf(aid, []LoggedEvent{{SequenceNum: 0}}); err == nil {
		t.Error("an event held without its bytes was stated")
	}
}

// signedRaw is raw signed by w, as a witness serves it.
func signedRaw(t *testing.T, w testWitness, raw []byte) SignedReply {
	t.Helper()
	ans, err := SignReply(raw, w.aid, w.sign)
	if err != nil {
		t.Fatal(err)
	}
	return ans
}

func TestAWitnessLocationIsBelievedOnlyAsTheWitnesssOwnHttpOrHttpsAddress(t *testing.T) {
	w, other := newTestWitness(t), newTestWitness(t)
	now := time.Now()
	ans, err := SignedWitnessLocation(w.aid, "https://w.example/witness/", now, w.sign)
	if err != nil {
		t.Fatal(err)
	}
	loc, err := VerifyWitnessLocation(ans, w.aid)
	if err != nil || loc.URL != "https://w.example/witness" {
		t.Fatalf("location = %+v, %v", loc, err)
	}
	if _, err := SignedWitnessLocation(w.aid, "ftp://w.example", now, w.sign); err == nil {
		t.Error("an ftp address was signed as a witness location")
	}
	loc2 := func(eid, scheme, u string) []byte {
		raw, err := keri.EndpointLocation(eid, scheme, u, ReplyDate(now))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	notice, err := BuildKeyStateNotice(w.aid, NoKeyState("EX"), now)
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := SignedWitnessLocation(other.aid, "https://o.example", now, other.sign)
	if err != nil {
		t.Fatal(err)
	}
	for name, ans := range map[string]SignedReply{
		"another witness's own location":                        theirs,
		"a location naming another witness, signed by this one": signedRaw(t, w, loc2(other.aid, "https", "https://o.example")),
		"a location naming this witness, signed by another":     signedRaw(t, other, loc2(w.aid, "https", "https://w.example")),
		"an ftp location, signed":                               signedRaw(t, w, loc2(w.aid, "ftp", "ftp://w.example")),
		"an address of another scheme than it says":             signedRaw(t, w, loc2(w.aid, "https", "http://w.example")),
		"an address with no host":                               signedRaw(t, w, loc2(w.aid, "https", "https://")),
		"an address with a user and password":                   signedRaw(t, w, loc2(w.aid, "http", "http://u:p@w.example/x")),
		"an address with a query":                               signedRaw(t, w, loc2(w.aid, "https", "https://w.example/x?y=1")),
		"an address with a fragment":                            signedRaw(t, w, loc2(w.aid, "https", "https://w.example/x#z")),
		"a withdrawn (empty) address":                           signedRaw(t, w, loc2(w.aid, "https", "")),
		"a key state notice offered as a location":              signedRaw(t, w, notice),
	} {
		if _, err := VerifyWitnessLocation(ans, w.aid); err == nil {
			t.Errorf("%s was believed", name)
		}
	}
}

// A notice that states a key state is read as it states it, and one whose
// statement cannot be KERI's is refused.
func TestAKeyStateNoticeIsReadOnlyAsKERIWritesIt(t *testing.T) {
	w, other := newTestWitness(t), newTestWitness(t)
	aid := "EAbcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"
	now := time.Now()
	stating := func(s, d string) SignedReply {
		rec := NoKeyState(aid)
		rec.S, rec.D = s, d
		ans, err := SignedKeyStateNotice(w.aid, rec, now, w.sign)
		if err != nil {
			t.Fatal(err)
		}
		return ans
	}
	st, err := VerifyKeyStateNotice(stating("a", "EX"), w.aid, aid, now)
	if err != nil || st.SN != 10 || st.SAID != "EX" {
		t.Fatalf("a notice at place a = %+v, %v; want place 10", st, err)
	}
	for _, s := range []string{"A", "01", "+1", "-1", "80000000"} {
		if _, err := VerifyKeyStateNotice(stating(s, "EX"), w.aid, aid, now); err == nil {
			t.Errorf("a notice at place %q was believed", s)
		}
	}
	if _, err := VerifyKeyStateNotice(stating("1", ""), w.aid, aid, now); err == nil {
		t.Error("a notice with a place and no event was believed")
	}
	if _, err := VerifyKeyStateNotice(stating("", "EX"), w.aid, aid, now); err == nil {
		t.Error("a notice with an event and no place was believed")
	}

	// Signed by the witness asked, but for another witness's route.
	data, _ := json.Marshal(NoKeyState(aid))
	misrouted, err := keri.BuildReply(keri.ReplyInput{Route: KeyStateRoute(other.aid), DT: ReplyDate(now), Data: data})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyKeyStateNotice(signedRaw(t, w, misrouted), w.aid, aid, now); err == nil {
		t.Error("a notice on another witness's route was believed")
	}
	// Signed by the witness asked, but its digest does not commit to it.
	good, _ := base64.StdEncoding.DecodeString(stating("1", "EX").RpyB64)
	var m map[string]json.RawMessage
	if err := json.Unmarshal(good, &m); err != nil {
		t.Fatal(err)
	}
	tampered := []byte(strings.Replace(string(good), string(m["d"]), `"EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`, 1))
	if _, err := VerifyKeyStateNotice(signedRaw(t, w, tampered), w.aid, aid, now); err == nil {
		t.Error("a notice whose digest does not commit to it was believed")
	}
	// The witness's own key, written as a transferable key, is not a witness key.
	pub := w.priv.Public().(ed25519.PublicKey)
	asD, _ := keri.MatterQB64("D", pub)
	if _, err := VerifyKeyStateNotice(stating("", ""), asD, aid, now); err == nil {
		t.Error("a transferable key was taken for a witness key")
	}
	// Too long to be a notice.
	big := SignedReply{RpyB64: base64.StdEncoding.EncodeToString(make([]byte, maxNoticeBytes+1)), Signature: stating("", "").Signature}
	if _, err := VerifyKeyStateNotice(big, w.aid, aid, now); err == nil || !strings.Contains(err.Error(), "not readable") {
		t.Errorf("a notice over the bound = %v, want it refused unread", err)
	}
}

func TestASignerThatIsNotTheNamedWitnessSignsNothing(t *testing.T) {
	w, other := newTestWitness(t), newTestWitness(t)
	if _, err := SignedKeyStateNotice(w.aid, NoKeyState("EX"), time.Now(), other.sign); err == nil {
		t.Error("a notice naming one witness was signed by another")
	}
}
