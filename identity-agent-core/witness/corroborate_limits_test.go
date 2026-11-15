package witness

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/witnessproto"
	"identity-agent-core/drivers"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/login"
)

// Corroborate is what an outside verifier calls, so it checks the log it is
// given: a log whose signatures do not verify, or that is another identifier's
// log than the one asked about, is not corroborated by any number of witnesses.
func TestCorroborateChecksTheLogItIsGivenAndWhoseLogItIs(t *testing.T) {
	l := buildWitnessedLog(t, witnessesOf(2), 2, []int{0, 1})
	ws := l.witnessesHolding(t)
	if got := Corroborate(nil, registry(ws), l.prefix, l.records); !got.Corroborated() || got.Unverified != "" {
		t.Fatalf("the control did not corroborate: %+v", got)
	}

	// Signed by a key that is not the one in force: every witness still says it
	// holds exactly this log, and receipts are over the event's bytes.
	forged := make([]map[string]interface{}, len(l.records))
	copy(forged, l.records)
	forgedIxn := l.ixn(t, l.saids[1], l.key0, "forged")
	forgedIxn["witness_receipts"] = l.records[2]["witness_receipts"]
	forged[2] = forgedIxn
	if got := Corroborate(nil, registry(ws), l.prefix, forged); got.Unverified == "" || got.Corroborated() || got.Asked != 0 {
		t.Fatalf("a log with an event the identity's key did not sign was asked about: %+v", got)
	}

	// Another identifier's log, presented as the owner's.
	other := buildSignedLog(t)
	if got := Corroborate(nil, registry(ws), other.prefix+"x", l.records); got.Unverified == "" || got.Corroborated() {
		t.Fatalf("a log was corroborated for an identifier that is not its own: %+v", got)
	}
	if got := Corroborate(nil, registry(ws), other.prefix, l.records); got.Unverified == "" || got.Corroborated() {
		t.Fatalf("a log was corroborated as the log of another identifier: %+v", got)
	}
}

// The witnesses are asked together, under one deadline: four that each take a
// moment all answer inside it, and ones that never answer cost the deadline once.
func TestTheWitnessesAreAskedTogetherUnderOneDeadline(t *testing.T) {
	old := corroborationDeadline
	t.Cleanup(func() { corroborationDeadline = old })
	corroborationDeadline = 2 * time.Second

	l := buildWitnessedLog(t, witnessesOf(4), 4, []int{0, 1, 2, 3})
	ws := l.witnessesHolding(t)
	for _, w := range ws {
		w.delay = 700 * time.Millisecond
	}
	// One after the other these would take 2.8s, which is past the deadline.
	got := Corroborate(nil, registry(ws), l.prefix, l.records)
	if got.Asked != 4 || !got.Corroborated() {
		t.Fatalf("four slow witnesses were not asked together: %+v", got)
	}

	for _, w := range ws {
		w.delay = time.Minute
	}
	start := time.Now()
	got = Corroborate(nil, registry(ws), l.prefix, l.records)
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("witnesses that never answer held the check for %v, past its deadline", took)
	}
	if got.Failed != 4 || got.Asked != 0 || got.Corroborated() {
		t.Fatalf("witnesses that never answered were counted: %+v", got)
	}
}

// A witness the log names twice is asked once, and counted once.
func TestEachWitnessIsAskedOnce(t *testing.T) {
	l := buildWitnessedLog(t, witnessesOf(2), 2, []int{0, 1})
	ws := l.witnessesHolding(t)
	keys := []string{l.w.keys[0], l.w.keys[0], l.w.keys[1], l.w.keys[0]}
	got := CorroborateThrough(nil, registry(ws), l.prefix, l.records, keys)
	if got.Designated != 2 || got.Asked != 2 || got.Held != 2 {
		t.Fatalf("a witness named three times was counted more than once: %+v", got)
	}
	if n := ws[0].hits.Load(); n != 1 {
		t.Fatalf("a witness named three times was asked %d times", n)
	}
}

// The threshold a log needs is at least one witness's word, however the log
// states it, and a verdict whose Required is nothing never corroborates.
func TestNothingIsCorroboratedByNobody(t *testing.T) {
	if (Corroboration{ReceiptsMet: true, Required: 0, Held: 0}).Corroborated() {
		t.Fatal("a verdict that requires nobody corroborated")
	}
	// A log that designates no witness has a threshold of nothing. A caller that
	// asks a witness all the same (the keys are the caller's choice) is told the
	// log needs one witness's word, not none.
	gen, err := keri.GenerateSigner(true)
	if err != nil {
		t.Fatal(err)
	}
	next, _ := keri.GenerateSigner(true)
	icp, err := keri.BuildInception(keri.InceptionInput{Keys: []string{pub(t, gen)}, NextDigests: []string{digest(t, next)}})
	if err != nil {
		t.Fatal(err)
	}
	prefix := parsed(t, icp).Identifier
	recs := []map[string]interface{}{record(icp, signAt(t, gen, icp, keri.SamePlace(0)))}
	w := witnessesOf(1)
	aw := &aWitness{key: w.keys[0], seed: w.seeds[w.keys[0]], sn: 0, said: parsed(t, icp).SAID, at: time.Now()}
	aw.serve(t)
	got := CorroborateThrough(nil, registry([]*aWitness{aw}), prefix, recs, w.keys)
	if got.Required != 1 || got.Held != 1 {
		t.Fatalf("a log with a threshold of nothing was asked of with Required %d (held %d): %+v", got.Required, got.Held, got)
	}
}

// A witness that states a longer history and shows, as the next event, one the
// identity's keys in force did not sign has shown nothing.
func TestALongerHistoryShownWithTheWrongKeyIsNotShown(t *testing.T) {
	l := buildWitnessedLog(t, witnessesOf(2), 2, []int{0, 1})
	stale := l.records[:2]
	for name, signer := range map[string]keri.Signer{"the key in force": l.key1, "a key rotated away from": l.key0} {
		t.Run(name, func(t *testing.T) {
			ws := l.witnessesHolding(t)
			ws[1].sn, ws[1].said = 1, l.saids[1] // the other holds what was presented, and no more
			shown := l.ixn(t, l.saids[1], signer, "next")
			ws[0].events[2] = shown
			ws[0].said = parsed(t, mustRawOf(shown)).SAID
			got := Corroborate(nil, registry(ws), l.prefix, stale)
			if want := signer == l.key1; got.Contradicted != want {
				t.Fatalf("contradicted = %v, want %v: %+v", got.Contradicted, want, got)
			}
		})
	}
}

// A witness is never sent somewhere else by a redirect, whether the caller gave
// a client or not: what answers is what the registry or the witness's own
// signed location named.
func TestARedirectIsNotFollowed(t *testing.T) {
	l := buildWitnessedLog(t, witnessesOf(1), 1, []int{0})
	behind := l.witnessesHolding(t)[0] // answers properly, wherever it is reached
	for name, client := range map[string]*http.Client{
		"no client given": nil,
		"a client given":  {Timeout: 5 * time.Second},
	} {
		t.Run(name, func(t *testing.T) {
			front := l.witnessesHolding(t)[0]
			front.redirectTo = behind.srv.URL
			got := Corroborate(client, registry([]*aWitness{front}), l.prefix, l.records)
			if got.Asked != 0 || got.Failed != 1 || got.Corroborated() {
				t.Fatalf("a witness's redirect was followed: %+v", got)
			}
		})
	}
}

// A witness's own signed location is refused when it names an internal address,
// and so is one that names a name that resolves to one: a witness could
// otherwise aim this machine at its own services. A public address is taken.
func TestASignedLocationThatIsInternalIsNotWentTo(t *testing.T) {
	w := witnessesOf(1)
	key, seed := w.keys[0], w.seeds[w.keys[0]]
	// Anything public until the loop below says otherwise: the probe of the hint is answered too.
	locatedAt := "http://203.0.113.7:8080"
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		raw, err := witnessproto.BuildWitnessLocation(key, locatedAt, time.Now())
		if err != nil {
			t.Error(err)
			return
		}
		sig, _ := login.SignString(string(raw), seed)
		_ = json.NewEncoder(rw).Encode(witnessproto.SignedReply{RpyB64: base64.StdEncoding.EncodeToString(raw), Signature: sig})
	}))
	defer srv.Close()

	// A hint the registry did not write as a local address: the same server, by a
	// name that is not literally one. foo.localhost is loopback for the system.
	hint := strings.Replace(srv.URL, "127.0.0.1", "foo.localhost", 1)
	client := &http.Client{Timeout: 5 * time.Second}
	if resp, err := client.Get(hint); err != nil {
		t.Skipf("this machine does not resolve foo.localhost: %v", err)
	} else {
		resp.Body.Close()
	}
	ctx := context.Background()
	for _, internal := range []string{
		"http://127.0.0.1:9", "http://10.1.2.3", "http://192.168.0.5:8080", "http://169.254.169.254",
		"http://[::1]:80", "http://[fe80::1]", "http://100.64.0.1", "http://localhost:80", "http://foo.localhost:80",
	} {
		locatedAt = internal
		if got := LocateWitness(ctx, client, hint, key); got != hint {
			t.Errorf("a location at %s was taken: %s", internal, got)
		}
	}
	locatedAt = "http://203.0.113.7:8080"
	if got := LocateWitness(ctx, client, hint, key); got != locatedAt {
		t.Errorf("a public location was not taken: %s", got)
	}
	// A registry that itself writes a local address as the hint has chosen it.
	locatedAt = "http://127.0.0.1:9"
	if got := LocateWitness(ctx, client, srv.URL, key); got != locatedAt {
		t.Errorf("a local location was refused for a registry that wrote a local hint: %s", got)
	}
}

// The notice is the /ksn reply of the witness that gave it, as keripy writes it:
// the route names the signer, not the identifier, and what it carries is the
// whole key state record, not the place and digest alone.
func TestTheNoticeIsKeripysAndCarriesTheFullKeyState(t *testing.T) {
	s, _ := testService(t)
	w := witnessesOf(2)
	key := w.keys[0]
	s.SignReceipt = func(statement string) (string, string, error) {
		sig, err := login.SignString(statement, w.seeds[key])
		return key, sig, err
	}
	s.OurWitnessAID = func() (string, error) { return key, nil }
	l := buildWitnessedLog(t, w, 2, nil)
	for i, rec := range l.records {
		ev := parsed(t, mustRawOf(rec))
		if err := s.Store.StoreKelEvent(KelEvent{SignerAID: l.prefix, SequenceNum: i, EventSAID: ev.SAID,
			EventJSON: "{}", StoredAt: NowRFC3339(), RawBytesB64: rec["raw_bytes_b64"].(string),
			CesrSignature: rec["cesr_signature"].(string)}); err != nil {
			t.Fatal(err)
		}
	}
	ans, err := s.KeyStateNotice(l.prefix, true)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(ans.RpyB64)
	rep, err := keri.VerifyReply(raw)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Route != "/ksn/"+key {
		t.Fatalf("the route is %q, not /ksn/ and the signing witness %q", rep.Route, key)
	}
	var rec map[string]json.RawMessage
	if err := json.Unmarshal(rep.Data, &rec); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"vn", "i", "s", "p", "d", "f", "dt", "et", "kt", "k", "nt", "n", "bt", "b", "c", "ee", "di"} {
		if _, ok := rec[f]; !ok {
			t.Errorf("the key state record has no %q, which keripy's has", f)
		}
	}
	var st witnessproto.KeyStateRecord
	_ = json.Unmarshal(rep.Data, &st)
	last := parsed(t, mustRawOf(l.records[2]))
	est := parsed(t, mustRawOf(l.records[1]))
	if st.I != l.prefix || st.S != "2" || st.D != last.SAID || st.P != est.SAID || st.ET != "ixn" ||
		st.EE.S != "1" || st.EE.D != est.SAID || st.BT != "2" || len(st.B) != 2 || len(st.K) != 1 || st.K[0] != est.Keys[0] {
		t.Fatalf("the key state record is not the state of this log after its last event: %+v", st)
	}

	// A signer that is not the witness key the notice names makes no notice.
	s.SignReceipt = func(statement string) (string, string, error) {
		sig, err := login.SignString(statement, w.seeds[w.keys[1]])
		return w.keys[1], sig, err
	}
	if _, err := s.KeyStateNotice(l.prefix, true); err == nil {
		t.Fatal("a notice naming one witness was signed by another's key")
	}

	// A notice signed by the right key but naming another witness is not this
	// witness's: it was made for somebody else's answer and replayed.
	elsewhere, _ := witnessproto.BuildKeyStateNotice(w.keys[1], st, time.Now())
	sig, _ := login.SignString(string(elsewhere), w.seeds[key])
	replayed := witnessproto.SignedReply{RpyB64: base64.StdEncoding.EncodeToString(elsewhere), Signature: sig}
	if _, err := witnessproto.VerifyKeyStateNotice(replayed, key, l.prefix, time.Now()); err == nil {
		t.Fatal("a notice for another witness's route was taken")
	}
}

// The reader refuses a location whose scheme is not http or https, for that
// reason: the address's own scheme is not what decides it.
func TestALocationOfAnotherSchemeIsRefusedForItsScheme(t *testing.T) {
	w := witnessesOf(1)
	key, seed := w.keys[0], w.seeds[w.keys[0]]
	raw, err := keri.EndpointLocation(key, "ftp", "ftp://w.example", time.Now().UTC().Format("2006-01-02T15:04:05.000000+00:00"))
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := login.SignString(string(raw), seed)
	_, err = witnessproto.VerifyWitnessLocation(witnessproto.SignedReply{RpyB64: base64.StdEncoding.EncodeToString(raw), Signature: sig}, key)
	if err == nil || !strings.Contains(err.Error(), "scheme") {
		t.Fatalf("an ftp location was not refused for its scheme: %v", err)
	}
}

// A witness that states more and is refused the read of the event once, by a rate
// limit, still shows it on the second: the withheld rotation is still seen.
func TestAWithheldRotationIsStillSeenWhenTheFirstReadOfItFails(t *testing.T) {
	l := buildWitnessedLog(t, witnessesOf(2), 2, []int{0, 1})
	ws := l.witnessesHolding(t)
	ws[0].eventFails.Store(1)
	ws[1].sn, ws[1].said = 1, l.saids[1]
	got := Corroborate(nil, registry(ws), l.prefix, l.records[:2])
	if !got.Contradicted {
		t.Fatalf("a withheld rotation went unseen because one read failed: %+v", got)
	}
}

// No more witnesses than the bound are asked at once, however many a log names.
func TestOnlyAFixedNumberOfWitnessesAreAskedAtOnce(t *testing.T) {
	l := buildWitnessedLog(t, witnessesOf(1), 1, []int{0})
	ws := l.witnessesHolding(t)
	var keys []string
	for i := 0; i < maxWitnessesAsked; i++ {
		keys = append(keys, witnessesOf(1).keys[0])
	}
	keys = append(keys, ws[0].key) // the one past the bound
	got := CorroborateThrough(nil, registry(ws), l.prefix, l.records, keys)
	if got.Designated != maxWitnessesAsked+1 || got.Failed != maxWitnessesAsked+1 || ws[0].hits.Load() != 0 {
		t.Fatalf("a witness past the bound was asked (hits %d): %+v", ws[0].hits.Load(), got)
	}
}

// One hostile witness, first in the list, serves a copy of every event carrying
// receipts that have the shape of genuine ones (an indexed signature at each other
// witness's place) and are not. The other two witnesses' own receipts are served
// only in their own copies and the presented log carries none, and the log is
// still corroborated at its threshold of two: one witness out of three must not be
// able to refuse a genuine claim by spending the others' checks.
func TestAHostileWitnessFirstCannotSpendTheOthersChecks(t *testing.T) {
	l := buildWitnessedLog(t, witnessesOf(3), 2, nil)
	ws := l.witnessesHolding(t)
	copyOf := func() []map[string]interface{} {
		var out []map[string]interface{}
		for _, rec := range l.records {
			c := map[string]interface{}{}
			for k, v := range rec {
				c[k] = v
			}
			delete(c, "witness_receipts")
			out = append(out, c)
		}
		return out
	}
	receipt := func(rec map[string]interface{}, at int, over []byte) map[string]interface{} {
		key := l.w.keys[at]
		sig, err := drivers.SignEventReceipt(over, l.w.seeds[key], at)
		if err != nil {
			t.Fatal(err)
		}
		return map[string]interface{}{"witness": key, "cesr_signature": sig}
	}
	for j, w := range ws {
		rep := copyOf()
		for _, rec := range rep {
			raw := mustRawOf(rec)
			list := []interface{}{}
			if j == 0 {
				for at := 1; at <= 2; at++ {
					for n := 0; n < 3*maxReceiptsAllowance; n++ {
						list = append(list, receipt(rec, at, append(append([]byte{}, raw...), byte(n), 'x')))
					}
				}
			}
			rec["witness_receipts"] = append(list, receipt(rec, j, raw))
		}
		w.replica = rep
	}
	got := Corroborate(nil, registry(ws), l.prefix, l.records)
	if !got.Corroborated() {
		t.Fatalf("one hostile witness refused a genuinely receipted log: %+v", got)
	}
}

// maxReceiptsAllowance is the number of receipts per witness one source is
// checked for (drivers.maxReceiptChecksPerWitness, which is not exported).
const maxReceiptsAllowance = 4
