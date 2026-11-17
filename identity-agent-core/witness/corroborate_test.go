package witness

import (
	"encoding/base64"
	"encoding/json"
	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/witnessproto"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/drivers"
	"identity-agent-core/login"
)

// The witnesses a log designates are asked the way KERI asks them: the log must
// be receipted to its threshold at every establishment event, and a live answer
// signed by each witness's own key says whether the log is the whole of it. These
// stand up servers that answer like witnesses, because the question is who is
// asked and what they can prove.

// A real, signed log, so that what a witness hands back as "conflicting" can be
// told from junk by checking its signature, which is the only way it can be.
type signedLog struct {
	records             []map[string]interface{}
	prefix              string
	saids               []string
	witness             string
	key0, key1, key2    keri.Signer
	next0, next1, next2 string
}

func record(raw []byte, sig string) map[string]interface{} {
	return map[string]interface{}{"raw_bytes_b64": base64.StdEncoding.EncodeToString(raw), "cesr_signature": sig}
}

// buildSignedLog is icp (key0), rot to key1 (sn 1), ixn signed by key1 (sn 2).
func buildSignedLog(t *testing.T) *signedLog {
	t.Helper()
	l := &signedLog{}
	var err error
	gen := func(transferable bool) keri.Signer {
		s, e := keri.GenerateSigner(transferable)
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	l.key0, l.key1, l.key2 = gen(true), gen(true), gen(true)
	w := gen(false)
	l.witness = pub(t, w)
	icp, err := keri.BuildInception(keri.InceptionInput{Keys: []string{pub(t, l.key0)},
		NextDigests: []string{digest(t, l.key1)}, Witnesses: []string{l.witness}})
	if err != nil {
		t.Fatal(err)
	}
	ie := parsed(t, icp)
	l.prefix = ie.Identifier
	rot, err := keri.BuildRotation(keri.RotationInput{Prefix: l.prefix, PriorSAID: ie.SAID, SN: 1,
		Keys: []string{pub(t, l.key1)}, NextDigests: []string{digest(t, l.key2)}})
	if err != nil {
		t.Fatal(err)
	}
	re := parsed(t, rot)
	ixn := l.ixn(t, re.SAID, l.key1, "a")
	l.saids = []string{ie.SAID, re.SAID, parsed(t, mustRawOf(ixn)).SAID}
	l.records = []map[string]interface{}{
		record(icp, signAt(t, l.key0, icp, keri.SamePlace(0))),
		record(rot, signAt(t, l.key1, rot, keri.SamePlace(0))),
		ixn,
	}
	return l
}

func mustRawOf(rec map[string]interface{}) []byte {
	b, _ := base64.StdEncoding.DecodeString(rec["raw_bytes_b64"].(string))
	return b
}

// ixn is an interaction at sn 2 after prior, signed by by, carrying a seal
// that makes it a different event for a different tag.
func (l *signedLog) ixn(t *testing.T, prior string, by keri.Signer, tag string) map[string]interface{} {
	t.Helper()
	raw, err := keri.BuildInteraction(keri.InteractionInput{Prefix: l.prefix, PriorSAID: prior, SN: 2,
		Data: []json.RawMessage{json.RawMessage(`{"d":"E` + tag + `"}`)}})
	if err != nil {
		t.Fatal(err)
	}
	return record(raw, signAt(t, by, raw, keri.SamePlace(0)))
}

// A witnessed, signed log: icp (key0), rot to key1 (sn 1), ixn signed by key1
// (sn 2), witnessed by w with threshold toad, receipted by the witnesses in
// receiptedBy.
type witnessedLog struct {
	signedLog
	w    someWitnesses
	toad int
}

func buildWitnessedLog(t *testing.T, w someWitnesses, toad int, receiptedBy []int) *witnessedLog {
	t.Helper()
	gen := func() keri.Signer {
		s, err := keri.GenerateSigner(true)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	l := &witnessedLog{w: w, toad: toad}
	l.key0, l.key1, l.key2 = gen(), gen(), gen()
	icp, err := keri.BuildInception(keri.InceptionInput{Keys: []string{pub(t, l.key0)},
		NextDigests: []string{digest(t, l.key1)}, Witnesses: w.keys, Toad: &toad})
	if err != nil {
		t.Fatal(err)
	}
	ie := parsed(t, icp)
	l.prefix = ie.Identifier
	rot, err := keri.BuildRotation(keri.RotationInput{Prefix: l.prefix, PriorSAID: ie.SAID, SN: 1,
		Keys: []string{pub(t, l.key1)}, NextDigests: []string{digest(t, l.key2)},
		PriorWitnesses: w.keys, Toad: &toad})
	if err != nil {
		t.Fatal(err)
	}
	re := parsed(t, rot)
	ixn := l.ixn(t, re.SAID, l.key1, "a")
	l.saids = []string{ie.SAID, re.SAID, parsed(t, mustRawOf(ixn)).SAID}
	l.records = []map[string]interface{}{
		record(icp, signAt(t, l.key0, icp, keri.SamePlace(0))),
		record(rot, signAt(t, l.key1, rot, keri.SamePlace(0))),
		ixn,
	}
	for _, at := range receiptedBy {
		for i := 0; i < 2; i++ {
			l.receipt(t, i, at)
		}
	}
	return l
}

// receipt has witness at (its place in the list) receipt the event at place sn.
func (l *witnessedLog) receipt(t *testing.T, sn, at int) {
	t.Helper()
	key := l.w.keys[at]
	sig, err := drivers.SignEventReceipt(mustRawOf(l.records[sn]), l.w.seeds[key], at)
	if err != nil {
		t.Fatal(err)
	}
	cur, _ := l.records[sn]["witness_receipts"].([]interface{})
	l.records[sn]["witness_receipts"] = append(cur, map[string]interface{}{"witness": key, "cesr_signature": sig})
}

// buildNoticeOf is a notice by witnessKey that states the log of aid as being at
// place sn with digest said, for tests that have no whole log behind them.
func buildNoticeOf(witnessKey, aid string, sn int, said string, at time.Time) ([]byte, error) {
	rec := witnessproto.NoKeyState(aid)
	if sn >= 0 {
		rec.S, rec.D = strconv.FormatInt(int64(sn), 16), said
	}
	return witnessproto.BuildKeyStateNotice(witnessKey, rec, at)
}

// a witness is a server at a registered address that states what it holds, signed
// by the key it signs as.
type aWitness struct {
	key  string
	seed []byte
	// state is what it says it holds: the place and digest, -1 and "" for nothing.
	sn   int
	said string
	// at is the date it gives its notice.
	at time.Time
	// signAs is whose key signs its answers when it is not the witness at all.
	signAs []byte
	// replica and conflicting are what it serves, unsigned, as its copy.
	replica, conflicting []map[string]interface{}
	// events are the single events it hands over by place, as a controller
	// published them.
	events map[int]map[string]interface{}
	// eventFails is how many reads of one event it refuses (429) before serving.
	eventFails atomic.Int32
	// hits counts the key state notices it was asked for.
	hits atomic.Int32
	// delay is how long it takes to answer a key state notice.
	delay time.Duration
	// redirectTo, when set, is where it sends a key state request instead of
	// answering it.
	redirectTo string
	// location, when set, is the address it states for itself, signed.
	location string
	// noState serves no notice at all.
	noState bool
	srv     *httptest.Server
}

func (w *aWitness) serve(t *testing.T) {
	t.Helper()
	signer := w.seed
	if w.signAs != nil {
		signer = w.signAs
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/witness/ksn/", func(rw http.ResponseWriter, r *http.Request) {
		w.hits.Add(1)
		if w.redirectTo != "" {
			http.Redirect(rw, r, w.redirectTo+r.URL.Path, http.StatusFound)
			return
		}
		if w.delay > 0 {
			select {
			case <-time.After(w.delay):
			case <-r.Context().Done():
				return
			}
		}
		if w.noState {
			http.NotFound(rw, r)
			return
		}
		aid := strings.TrimPrefix(r.URL.Path, "/witness/ksn/")
		raw, err := buildNoticeOf(w.key, aid, w.sn, w.said, w.at)
		if err != nil {
			t.Error(err)
			return
		}
		sig, _ := login.SignString(string(raw), signer)
		_ = json.NewEncoder(rw).Encode(witnessproto.SignedReply{RpyB64: base64.StdEncoding.EncodeToString(raw), WitnessAID: w.key, Signature: sig})
	})
	mux.HandleFunc("/witness/kel/", func(rw http.ResponseWriter, r *http.Request) {
		if i := strings.LastIndex(r.URL.Path, "/event/"); i >= 0 {
			if w.eventFails.Add(-1) >= 0 {
				http.Error(rw, "slow down", http.StatusTooManyRequests)
				return
			}
			sn, _ := strconv.Atoi(r.URL.Path[i+len("/event/"):])
			ev, ok := w.events[sn]
			if !ok {
				http.NotFound(rw, r)
				return
			}
			_ = json.NewEncoder(rw).Encode(ev)
			return
		}
		_ = json.NewEncoder(rw).Encode(map[string]interface{}{"kel": w.replica, "conflicting": w.conflicting})
	})
	mux.HandleFunc("/witness/loc/", func(rw http.ResponseWriter, r *http.Request) {
		if w.location == "" {
			http.NotFound(rw, r)
			return
		}
		raw, err := witnessproto.BuildWitnessLocation(w.key, w.location, w.at)
		if err != nil {
			t.Error(err)
			return
		}
		sig, _ := login.SignString(string(raw), signer)
		_ = json.NewEncoder(rw).Encode(witnessproto.SignedReply{RpyB64: base64.StdEncoding.EncodeToString(raw), WitnessAID: w.key, Signature: sig})
	})
	w.srv = httptest.NewServer(mux)
	t.Cleanup(w.srv.Close)
}

// witnessesHolding makes the log's witnesses, each stating that it holds the
// whole log (or what the test then changes).
func (l *witnessedLog) witnessesHolding(t *testing.T) []*aWitness {
	t.Helper()
	var out []*aWitness
	for _, key := range l.w.keys {
		w := &aWitness{key: key, seed: l.w.seeds[key], sn: len(l.saids) - 1, said: l.saids[len(l.saids)-1],
			at: time.Now(), replica: l.records, events: map[int]map[string]interface{}{}}
		for i, rec := range l.records {
			w.events[i] = rec
		}
		w.serve(t)
		out = append(out, w)
	}
	return out
}

func registry(ws []*aWitness) []BootstrapWitness {
	var out []BootstrapWitness
	for _, w := range ws {
		out = append(out, BootstrapWitness{AID: w.key, WitnessKey: w.key, URL: w.srv.URL})
	}
	return out
}

// Receipts from every witness to the threshold, and each witness stating, signed
// and now, that the newest event is its own: the log is corroborated, and the
// verdict is reached from the registry, the receipts and the signatures only.
func TestALogReceiptedToItsThresholdAndHeldByItsWitnessesCorroborates(t *testing.T) {
	l := buildWitnessedLog(t, witnessesOf(2), 2, []int{0, 1})
	ws := l.witnessesHolding(t)
	got := Corroborate(nil, registry(ws), l.prefix, l.records)
	if !got.Corroborated() || got.Held != 2 || got.Asked != 2 || got.Required != 2 || !got.ReceiptsMet || len(got.Answers) != 2 {
		t.Fatalf("a log receipted to its threshold and held by its witnesses did not corroborate: %+v", got)
	}
}

// A presented log with receipts from fewer than bt of the witnesses in force is
// refused, however many witnesses say they hold it.
func TestALogReceiptedByFewerThanItsThresholdIsRefused(t *testing.T) {
	l := buildWitnessedLog(t, witnessesOf(2), 2, []int{0})
	ws := l.witnessesHolding(t)
	for _, w := range ws {
		w.replica = nil // what each witness serves carries no more receipts than the claim
	}
	got := Corroborate(nil, registry(ws), l.prefix, l.records)
	if got.Corroborated() || got.ReceiptsMet {
		t.Fatalf("a log with 1 receipt where 2 are needed corroborated: %+v", got)
	}
	if len(got.Unreceipted) != 2 || got.Unreceipted[0] != 0 || got.Unreceipted[1] != 1 {
		t.Fatalf("the establishment events that fall short were not named: %v", got.Unreceipted)
	}
	// Another witness's receipt of the same event, served beside it, is counted.
	l2 := buildWitnessedLog(t, witnessesOf(2), 2, []int{0})
	ws2 := l2.witnessesHolding(t)
	other := *l2
	other.records = append([]map[string]interface{}(nil), l2.records...)
	for i := range other.records {
		c := map[string]interface{}{}
		for k, v := range l2.records[i] {
			c[k] = v
		}
		other.records[i] = c
	}
	other.receipt(t, 0, 1)
	other.receipt(t, 1, 1)
	ws2[1].replica = other.records
	if got := Corroborate(nil, registry(ws2), l2.prefix, l2.records); !got.Corroborated() {
		t.Fatalf("a receipt a witness serves for the event was not counted: %+v", got)
	}
}

// A receipt one witness issued twice, or one a witness the log never designated
// issued, is not a second witness.
func TestOneWitnessReceiptingTwiceIsNotTwoWitnesses(t *testing.T) {
	l := buildWitnessedLog(t, witnessesOf(2), 2, []int{0})
	l.receipt(t, 0, 0)
	l.receipt(t, 1, 0)
	ws := l.witnessesHolding(t)
	if got := Corroborate(nil, registry(ws), l.prefix, l.records); got.ReceiptsMet || got.Corroborated() {
		t.Fatalf("one witness's receipt counted twice met a threshold of 2: %+v", got)
	}
}

// The withheld rotation: every receipt on the stale log is valid, and the
// witnesses, asked now, state, signed, that they hold more.
func TestAWitnessStatingItHoldsALongerHistoryRefusesTheClaim(t *testing.T) {
	l := buildWitnessedLog(t, witnessesOf(2), 2, []int{0, 1})
	ws := l.witnessesHolding(t)
	stale := l.records[:2]
	// The witnesses hold sn 2; the claim shows up to sn 1, with every receipt in order, which
	// is why a receipt cannot be what catches it.
	got := Corroborate(nil, registry(ws), l.prefix, stale)
	if !got.Contradicted || got.Corroborated() {
		t.Fatalf("a log with its last event cut off was not refused: %+v", got)
	}
}

// A different event at a place the claim shows one is a fork, when the witness
// shows it validly signed.
func TestAWitnessShowingADifferentSignedEventAtThePlaceRefusesTheClaim(t *testing.T) {
	l := buildWitnessedLog(t, witnessesOf(2), 2, []int{0, 1})
	ws := l.witnessesHolding(t)
	rival := l.ixn(t, l.saids[1], l.key1, "rival")
	ws[0].said = parsed(t, mustRawOf(rival)).SAID
	ws[0].events[2] = rival
	if got := Corroborate(nil, registry(ws), l.prefix, l.records); !got.Contradicted {
		t.Fatalf("a witness showing a validly signed fork did not refuse the claim: %+v", got)
	}
}

// One witness saying, and showing nothing, that it holds a different or a longer
// history must not veto a genuine claim: any server can say so. It has not
// answered; the witnesses that did decide.
func TestAWitnessThatOnlySaysItHoldsSomethingElseCannotRefuseAGenuineClaim(t *testing.T) {
	l := buildWitnessedLog(t, witnessesOf(3), 2, []int{0, 1, 2})
	cases := map[string]func(w *aWitness){
		"a different event": func(w *aWitness) { w.said = "EADifferentEventSaid0000000000000000000000" },
		"a longer history":  func(w *aWitness) { w.sn, w.said = 9, "ELongerHistorySaid00000000000000000000000" },
		"an event not signed by the identity": func(w *aWitness) {
			w.said = parsed(t, mustRawOf(l.ixn(t, l.saids[1], l.key0, "x"))).SAID
			w.events[2] = l.ixn(t, l.saids[1], l.key0, "x") // signed by a key already rotated away from
		},
		"an event that does not follow the log": func(w *aWitness) {
			w.sn, w.said = 3, "ENotTheNextEventSaid00000000000000000000"
			w.events[3] = l.ixn(t, l.saids[1], l.key1, "gap")
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			ws := l.witnessesHolding(t)
			setup(ws[0])
			got := Corroborate(nil, registry(ws), l.prefix, l.records)
			if got.Contradicted {
				t.Fatalf("one witness's unproven word refused a genuine claim: %+v", got)
			}
			if got.Failed != 1 || got.Held != 2 || !got.Corroborated() {
				t.Fatalf("the two witnesses that confirmed did not carry it: %+v", got)
			}
		})
	}
}

// A server at a registered witness address that is not the witness cannot sign
// as its key, so what it says is ignored, however much it says.
func TestAServerThatCannotSignAsTheWitnessIsIgnored(t *testing.T) {
	l := buildWitnessedLog(t, witnessesOf(2), 2, []int{0, 1})
	ws := l.witnessesHolding(t)
	impostor := witnessesOf(1)
	ws[0].signAs = impostor.seeds[impostor.keys[0]]
	ws[0].srv.Close()
	ws[0].serve(t)
	// And it claims the log is longer, which a witness could say.
	ws[0].sn, ws[0].said = 9, "EImpostorSaysTheLogIsLonger00000000000000"
	got := Corroborate(nil, registry(ws), l.prefix, l.records)
	if got.Contradicted || got.Failed != 1 || got.Asked != 1 || got.Held != 1 {
		t.Fatalf("an impostor at a registered address was believed, or counted: %+v", got)
	}
	if got.Corroborated() {
		t.Fatal("one witness of two corroborated a threshold of 2")
	}
}

// What a witness serves as its copy of the log, unsigned, is not evidence of
// what it holds: a longer copy there does not refuse the claim, and a whole one
// does not corroborate it.
func TestAnUnsignedCopyOfTheLogIsNotAnAnswer(t *testing.T) {
	l := buildWitnessedLog(t, witnessesOf(2), 2, []int{0, 1})
	ws := l.witnessesHolding(t)
	for _, w := range ws {
		w.noState = true
	}
	got := Corroborate(nil, registry(ws), l.prefix, l.records[:2])
	if got.Contradicted || got.Corroborated() || got.Asked != 0 || got.Failed != 2 {
		t.Fatalf("an unsigned copy was taken for an answer: %+v", got)
	}
}

// A notice that is not dated now is a replay, however well it is signed.
func TestAStaleNoticeIsNotBelieved(t *testing.T) {
	l := buildWitnessedLog(t, witnessesOf(2), 2, []int{0, 1})
	ws := l.witnessesHolding(t)
	ws[0].at = time.Now().Add(-2 * witnessproto.KeyStateFreshness)
	ws[1].at = time.Now().Add(2 * witnessproto.KeyStateFreshness)
	got := Corroborate(nil, registry(ws), l.prefix, l.records)
	if got.Asked != 0 || got.Failed != 2 || got.Corroborated() {
		t.Fatalf("a notice dated %v from now was believed: %+v", 2*witnessproto.KeyStateFreshness, got)
	}
}

// A witness that holds nothing, or less, is not a confirmation, however it is
// signed.
func TestAWitnessHoldingNothingOrLessDoesNotConfirm(t *testing.T) {
	l := buildWitnessedLog(t, witnessesOf(2), 2, []int{0, 1})
	ws := l.witnessesHolding(t)
	ws[0].sn, ws[0].said = -1, ""
	ws[1].sn, ws[1].said = 1, l.saids[1]
	got := Corroborate(nil, registry(ws), l.prefix, l.records)
	if got.Empty != 1 || got.Behind != 1 || got.Held != 0 || got.Corroborated() || got.Contradicted {
		t.Fatalf("%+v", got)
	}
}

// The registry says where to look and nothing more. A witness that has moved
// states, signed by its key, where it is reached now; and a location signed by
// any other key is no location.
func TestAWitnessIsFoundWhereItsOwnSignedLocationSays(t *testing.T) {
	l := buildWitnessedLog(t, witnessesOf(1), 1, []int{0})
	ws := l.witnessesHolding(t)
	moved := ws[0]
	// The registered address has nothing but the signed statement of where the
	// witness is now.
	hint := &aWitness{key: moved.key, seed: moved.seed, at: time.Now(), location: moved.srv.URL, noState: true}
	hint.serve(t)
	pool := []BootstrapWitness{{AID: moved.key, WitnessKey: moved.key, URL: hint.srv.URL}}
	got := Corroborate(nil, pool, l.prefix, l.records)
	if !got.Corroborated() || got.Answers[0].URL != moved.srv.URL {
		t.Fatalf("a witness was not found where its own signed location says: %+v", got)
	}

	other := witnessesOf(1)
	liar := &aWitness{key: moved.key, seed: moved.seed, signAs: other.seeds[other.keys[0]], at: time.Now(),
		location: moved.srv.URL, noState: true}
	liar.serve(t)
	pool = []BootstrapWitness{{AID: moved.key, WitnessKey: moved.key, URL: liar.srv.URL}}
	got = Corroborate(nil, pool, l.prefix, l.records)
	if got.Corroborated() || got.Failed != 1 {
		t.Fatalf("a location signed by another key was followed: %+v", got)
	}
}

func TestAWitnessTheRegistryDoesNotListIsNotAsked(t *testing.T) {
	l := buildWitnessedLog(t, witnessesOf(1), 1, []int{0})
	ws := l.witnessesHolding(t)
	pool := []BootstrapWitness{{AID: "EOther", WitnessKey: "BSomeOtherWitnessKey0000000000000000000000000", URL: ws[0].srv.URL}}
	got := Corroborate(nil, pool, l.prefix, l.records)
	if got.Corroborated() || got.Asked != 0 || got.Failed != 1 || len(got.Answers) != 0 {
		t.Fatalf("a server claiming to be the witness was asked: %+v", got)
	}
	if got := Corroborate(nil, nil, l.prefix, l.records); got.Corroborated() || got.Asked != 0 || got.Failed != 1 {
		t.Fatalf("an empty registry asked somebody: %+v", got)
	}
}

func TestALogDesignatingNoWitnessAsksNobody(t *testing.T) {
	l := buildWitnessedLog(t, witnessesOf(1), 1, []int{0})
	ws := l.witnessesHolding(t)
	got := CorroborateThrough(nil, registry(ws), l.prefix, l.records, nil)
	if got.Designated != 0 || got.Asked != 0 || got.Corroborated() {
		t.Fatalf("%+v", got)
	}
}

// A log built and receipted by keripy itself, with receipts keripy's Hab.witness
// made, is corroborated with nothing of ours in the way it was made.
func TestALogBuiltAndReceiptedByKeripyCorroborates(t *testing.T) {
	b, err := os.ReadFile("../witnessproto/testdata/keripy_witness_receipts.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Controller   string `json:"controller"`
		EventSAID    string `json:"event_said"`
		EventB64     string `json:"event_b64"`
		MessageB64   string `json:"event_message_b64"`
		Witnesses    []string
		WitnessesRaw json.RawMessage `json:"witnesses"`
		Receipts     []struct {
			Witness    string `json:"witness"`
			SeedB64    string `json:"seed_b64"`
			Index      int    `json:"index"`
			Attachment string `json:"attachment"`
		} `json:"receipts"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	// The controller's signature is the last 88 characters of keripy's message.
	msg, _ := base64.StdEncoding.DecodeString(v.MessageB64)
	sig := string(msg[len(msg)-88:])
	rec := map[string]interface{}{"raw_bytes_b64": v.EventB64, "cesr_signature": sig}
	var wits []*aWitness
	for _, r := range v.Receipts {
		seed, _ := base64.StdEncoding.DecodeString(r.SeedB64)
		rec["witness_receipts"] = append(asList(rec["witness_receipts"]),
			map[string]interface{}{"witness": r.Witness, "cesr_signature": r.Attachment[8:]})
		w := &aWitness{key: r.Witness, seed: seed, sn: 0, said: v.EventSAID, at: time.Now()}
		w.serve(t)
		wits = append(wits, w)
	}
	log := []map[string]interface{}{rec}
	got := Corroborate(nil, registry(wits), v.Controller, log)
	if !got.Corroborated() || got.Required != 2 || got.Held != 2 {
		t.Fatalf("a log keripy built and receipted was not corroborated: %+v", got)
	}
}

func asList(v interface{}) []interface{} {
	l, _ := v.([]interface{})
	return l
}

// Only a validly signed rival is duplicity: what else a witness hands back
// proves nothing.
func TestOnlyAValidlySignedRivalIsDuplicity(t *testing.T) {
	l := buildWitnessedLog(t, witnessesOf(1), 1, []int{0})
	staleKey := l.ixn(t, l.saids[1], l.key0, "b")
	valid := l.ixn(t, l.saids[1], l.key1, "c")
	other := buildSignedLog(t)
	elsewhere := other.ixn(t, other.saids[1], other.key1, "d")

	cases := []struct {
		name        string
		conflicting []map[string]interface{}
		ignored     int
		fails       bool
	}{
		{"the held event itself", []map[string]interface{}{l.records[2]}, 1, false},
		{"garbage bytes", []map[string]interface{}{{"raw_bytes_b64": base64.StdEncoding.EncodeToString([]byte("not an event")), "cesr_signature": "x"}}, 1, false},
		{"an empty object", []map[string]interface{}{{}}, 1, false},
		{"a key already rotated away from", []map[string]interface{}{staleKey}, 1, false},
		{"another identifier's event", []map[string]interface{}{elsewhere}, 1, false},
		{"a validly signed rival", []map[string]interface{}{valid}, 0, true},
		{"junk beside a validly signed rival", []map[string]interface{}{{}, valid}, 1, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ws := l.witnessesHolding(t)
			ws[0].conflicting = c.conflicting
			got := Corroborate(nil, registry(ws), l.prefix, l.records)
			if got.Contradicted != c.fails {
				t.Fatalf("contradicted = %v, want %v: %+v", got.Contradicted, c.fails, got)
			}
			if !c.fails && !got.Corroborated() {
				t.Fatalf("an honest claim was refused over an invalid conflicting entry: %+v", got)
			}
			if len(got.Answers) != 1 || got.Answers[0].Ignored != c.ignored {
				t.Fatalf("ignored = %+v, want %d", got.Answers, c.ignored)
			}
		})
	}
}

// A key state notice that was not made for this identifier, by this witness, as
// the /ksn reply, is not one.
func TestAKeyStateNoticeIsReadOnlyAsWhatItIs(t *testing.T) {
	w := witnessesOf(2)
	key, seed := w.keys[0], w.seeds[w.keys[0]]
	now := time.Now()
	make := func(aid string, sn int, at time.Time, as []byte) witnessproto.SignedReply {
		raw, err := buildNoticeOf(key, aid, sn, "ESaid00000000000000000000000000000000000000", at)
		if err != nil {
			t.Fatal(err)
		}
		sig, _ := login.SignString(string(raw), as)
		return witnessproto.SignedReply{RpyB64: base64.StdEncoding.EncodeToString(raw), Signature: sig}
	}
	if st, err := witnessproto.VerifyKeyStateNotice(make("EAid", 255, now, seed), key, "EAid", now); err != nil || st.SN != 255 {
		t.Fatalf("a good notice was refused: %v %+v", err, st)
	}
	if _, err := witnessproto.VerifyKeyStateNotice(make("EAid", 1, now, seed), key, "EOther", now); err == nil {
		t.Fatal("a notice about another identifier was taken")
	}
	if _, err := witnessproto.VerifyKeyStateNotice(make("EAid", 1, now, w.seeds[w.keys[1]]), key, "EAid", now); err == nil {
		t.Fatal("a notice signed by another key was taken")
	}
	// Altered after it was signed.
	good := make("EAid", 1, now, seed)
	raw, _ := base64.StdEncoding.DecodeString(good.RpyB64)
	good.RpyB64 = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(raw), `"s":"1"`, `"s":"0"`, 1)))
	if _, err := witnessproto.VerifyKeyStateNotice(good, key, "EAid", now); err == nil {
		t.Fatal("an altered notice was taken")
	}
}

// The notice this service serves is the notice the checker reads: signed by the
// witnessing key, for the log it holds, and the same for a log not held as for
// one the asker may not read.
func TestTheNoticeAWitnessServesIsTheOneTheCheckerReads(t *testing.T) {
	s, _ := testService(t)
	w := witnessesOf(1)
	key := w.keys[0]
	s.SignReceipt = func(statement string) (string, string, error) {
		sig, err := login.SignString(statement, w.seeds[key])
		return key, sig, err
	}
	s.OurWitnessAID = func() (string, error) { return key, nil }
	l := buildWitnessedLog(t, witnessesOf(1), 1, nil)
	ev := parsed(t, mustRawOf(l.records[0]))
	if err := s.Store.StoreKelEvent(KelEvent{SignerAID: l.prefix, SequenceNum: 0, EventSAID: ev.SAID,
		EventJSON: "{}", StoredAt: NowRFC3339(), RawBytesB64: base64.StdEncoding.EncodeToString(mustRawOf(l.records[0]))}); err != nil {
		t.Fatal(err)
	}
	ans, err := s.KeyStateNotice(l.prefix, true)
	if err != nil {
		t.Fatal(err)
	}
	st, err := witnessproto.VerifyKeyStateNotice(ans, key, l.prefix, time.Now())
	if err != nil || st.SN != 0 || st.SAID != ev.SAID {
		t.Fatalf("the served notice was not read as served: %v %+v", err, st)
	}
	ans, _ = s.KeyStateNotice(l.prefix, false)
	if st, err := witnessproto.VerifyKeyStateNotice(ans, key, l.prefix, time.Now()); err != nil || st.SN != -1 {
		t.Fatalf("an asker who may not read was told what is held: %v %+v", err, st)
	}
	s.OurWitnessAID = nil
	if _, err := s.WitnessLocationNotice("https://w.example/"); err == nil {
		t.Fatal("a location was signed with no witnessing identity to say whose it is")
	}
	s.OurWitnessAID = func() (string, error) { return key, nil }
	loc, err := s.WitnessLocationNotice("https://w.example/")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := witnessproto.VerifyWitnessLocation(loc, key); err != nil || got.URL != "https://w.example" {
		t.Fatalf("the served location was not read as served: %v %+v", err, got)
	}
}

// After a rotation that cuts a witness and adds another, the witnesses to ask
// are the ones in force at the end, not the inception's: the cut one holds
// less, and must not stand in the way of a log its replacement and the other
// witness hold.
func TestAfterARotationTheWitnessesInForceAreTheOnesAsked(t *testing.T) {
	w := witnessesOf(3) // 0 and 1 at inception; the rotation cuts 1 and adds 2
	toad := 2
	gen := func() keri.Signer { s, _ := keri.GenerateSigner(true); return s }
	k0, k1, k2 := gen(), gen(), gen()
	icp, err := keri.BuildInception(keri.InceptionInput{Keys: []string{pub(t, k0)},
		NextDigests: []string{digest(t, k1)}, Witnesses: w.keys[:2], Toad: &toad})
	if err != nil {
		t.Fatal(err)
	}
	ie := parsed(t, icp)
	rot, err := keri.BuildRotation(keri.RotationInput{Prefix: ie.Identifier, PriorSAID: ie.SAID, SN: 1,
		Keys: []string{pub(t, k1)}, NextDigests: []string{digest(t, k2)},
		PriorWitnesses: w.keys[:2], Cuts: []string{w.keys[1]}, Adds: []string{w.keys[2]}, Toad: &toad})
	if err != nil {
		t.Fatal(err)
	}
	l := &witnessedLog{w: w, toad: toad}
	l.prefix = ie.Identifier
	l.saids = []string{ie.SAID, parsed(t, rot).SAID}
	l.records = []map[string]interface{}{
		record(icp, signAt(t, k0, icp, keri.SamePlace(0))),
		record(rot, signAt(t, k1, rot, keri.SamePlace(0))),
	}
	// Inception: witnesses 0 and 1 (places 0, 1). Rotation: 0 and 2 (places 0, 1).
	l.receipt(t, 0, 0)
	l.receipt(t, 0, 1)
	for i, at := range []int{0, 2} {
		key := w.keys[at]
		sig, err := drivers.SignEventReceipt(mustRawOf(l.records[1]), w.seeds[key], i)
		if err != nil {
			t.Fatal(err)
		}
		l.records[1]["witness_receipts"] = append(asList(l.records[1]["witness_receipts"]),
			map[string]interface{}{"witness": key, "cesr_signature": sig})
	}
	if got := WitnessKeysInForce(l.records); len(got) != 2 || got[0] != w.keys[0] || got[1] != w.keys[2] {
		t.Fatalf("the witnesses in force at the end were read as %v", got)
	}
	ws := l.witnessesHolding(t)
	pool := []BootstrapWitness{
		{AID: w.keys[0], WitnessKey: w.keys[0], URL: ws[0].srv.URL},
		{AID: w.keys[2], WitnessKey: w.keys[2], URL: ws[2].srv.URL},
	}
	ws[1].sn, ws[1].said = 0, l.saids[0] // the cut witness holds less, and is not asked
	got := Corroborate(nil, pool, l.prefix, l.records)
	if !got.Corroborated() || got.Designated != 2 {
		t.Fatalf("a rotated log held by the witnesses in force did not corroborate: %+v", got)
	}
}

// A location is the witness's own, for an http or https address, on the location
// route; a notice is not a location and a location is not a notice.
func TestALocationIsReadOnlyAsWhatItIs(t *testing.T) {
	w := witnessesOf(2)
	key, seed := w.keys[0], w.seeds[w.keys[0]]
	reply := func(eid, url string, as []byte) witnessproto.SignedReply {
		raw, err := witnessproto.BuildWitnessLocation(eid, url, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		sig, _ := login.SignString(string(raw), as)
		return witnessproto.SignedReply{RpyB64: base64.StdEncoding.EncodeToString(raw), Signature: sig}
	}
	if _, err := witnessproto.VerifyWitnessLocation(reply(key, "https://w.example", seed), key); err != nil {
		t.Fatalf("a good location was refused: %v", err)
	}
	if _, err := witnessproto.VerifyWitnessLocation(reply(w.keys[1], "https://w.example", seed), key); err == nil {
		t.Fatal("a location for another witness was taken")
	}
	// The builder will not write an address of another scheme, so a witness that did is written by hand.
	if _, err := witnessproto.BuildWitnessLocation(key, "ftp://w.example", time.Now()); err == nil {
		t.Fatal("an address that is not http or https was signed")
	}
	ftp, err := keri.EndpointLocation(key, "ftp", "ftp://w.example", witnessproto.ReplyDate(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	ftpSig, _ := login.SignString(string(ftp), seed)
	if _, err := witnessproto.VerifyWitnessLocation(witnessproto.SignedReply{RpyB64: base64.StdEncoding.EncodeToString(ftp), Signature: ftpSig}, key); err == nil {
		t.Fatal("an address that is not http or https was taken")
	}
	notice, _ := buildNoticeOf(key, "EAid", 1, "ESaid0000000000000000000000000000000000000", time.Now())
	sig, _ := login.SignString(string(notice), seed)
	if _, err := witnessproto.VerifyWitnessLocation(witnessproto.SignedReply{RpyB64: base64.StdEncoding.EncodeToString(notice), Signature: sig}, key); err == nil {
		t.Fatal("a key state notice was taken for a location")
	}
	loc := reply(key, "https://w.example", seed)
	if _, err := witnessproto.VerifyKeyStateNotice(loc, key, "EAid", time.Now()); err == nil {
		t.Fatal("a location was taken for a key state notice")
	}
}
