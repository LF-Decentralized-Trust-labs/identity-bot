package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/measurementlist/anchored"
	"identity-agent-core/witness"
)

// The publisher's list, checked with its witnesses, is the policy when it
// holds; the environment's list is only the bootstrap for when none has ever
// been accepted. A list that fails is never widened by, and never narrows, the
// bootstrap. The publisher, its key history, its two lists (sequence 7 and 8)
// and the witnesses' signing seeds are the committed vectors the checker's own
// tests are held to (measurementlist/anchored/testdata/server_vectors.json).

type listVectors struct {
	Publisher  string            `json:"publisher"`
	Inception  string            `json:"inception_b64"`
	Registry   string            `json:"registry"`
	Schema     string            `json:"schema"`
	WitnessAID []string          `json:"witness_aids"`
	WitnessSd  []string          `json:"witness_seeds_hex"`
	Bundles    map[string]string `json:"bundles"`
	Measure    map[string]string `json:"measurement_of"`
	Now        string            `json:"now"`
}

// theWitnessesOfThePublisher answer a tip question the way witness.Service does,
// for the bundle the fixture says the witnesses hold.
type theWitnessesOfThePublisher struct {
	v      listVectors
	holds  string // which bundle's tip the witnesses hold
	silent bool
	asked  int
}

func (w *theWitnessesOfThePublisher) AskTips(_ context.Context, aid string, _ []string) []witness.AskedTip {
	w.asked++
	if w.silent {
		return nil
	}
	b, err := anchored.ParseBundle([]byte(w.v.Bundles[w.holds]))
	if err != nil {
		panic(err)
	}
	raw, _ := keri.EventOfMessage(b.KEL[len(b.KEL)-1])
	ev, _ := keri.ParseEvent(raw)
	var out []witness.AskedTip
	for i, sd := range w.v.WitnessSd {
		seed, _ := hex.DecodeString(sd)
		sg, _ := keri.NewSoftwareSigner(seed, false)
		nonce := strings.Repeat(string(rune('a'+i)), 8) + hex.EncodeToString([]byte{byte(w.asked), byte(i)}) + "-nonce-nonce"
		sig, _ := sg.Sign([]byte(witness.TipStatement(aid, nonce, int(ev.SN), ev.SAID)))
		q, _ := keri.MatterQB64("0B", sig)
		out = append(out, witness.AskedTip{Nonce: nonce, Answer: witness.TipAnswer{AID: aid, Nonce: nonce, SN: int(ev.SN),
			SAID: ev.SAID, WitnessAID: w.v.WitnessAID[i], Signature: q}})
	}
	return out
}

type listFixture struct {
	t     *testing.T
	v     listVectors
	dir   string
	now   time.Time
	w     *theWitnessesOfThePublisher
	lists *measurementLists
}

func newListFixture(t *testing.T) *listFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "measurementlist", "anchored", "testdata", "server_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	f := &listFixture{t: t, dir: t.TempDir()}
	if err := json.Unmarshal(raw, &f.v); err != nil {
		t.Fatal(err)
	}
	f.now, _ = time.Parse(time.RFC3339, f.v.Now)
	f.w = &theWitnessesOfThePublisher{v: f.v, holds: "seq7"}
	f.lists = f.newCore()
	t.Setenv("AGENT_ACCEPTED_MEASUREMENTS", "")
	return f
}

// newCore is a core started on the same data directory: nothing staged.
func (f *listFixture) newCore() *measurementLists {
	return &measurementLists{dataDir: f.dir, now: func() time.Time { return f.now },
		pin: func() (anchored.Pin, error) {
			return anchored.ParsePin(f.v.Publisher, f.v.Inception, f.v.Registry, f.v.Schema)
		},
		asker: func() anchored.TipAsker { return f.w }}
}

func (f *listFixture) submit(which string) error {
	f.t.Helper()
	f.w.holds = which
	_, err := f.lists.check(context.Background(), []byte(f.v.Bundles[which]))
	return err
}

func (f *listFixture) server(l *measurementLists) *CoreServer {
	s := &CoreServer{localOwnerSecret: testOwnerSecret, measurementLists: l}
	s.measurementPolicy = func(time.Time) ([][]byte, string) {
		m, why, _ := l.policy("individual", f.now)
		return m, why
	}
	return s
}

func (f *listFixture) measurement(which string) []byte { return mustHex(f.t, f.v.Measure[which]) }

func mustHex(t *testing.T, h string) []byte {
	t.Helper()
	m, err := parseMeasurements([]string{h})
	if err != nil {
		t.Fatal(err)
	}
	return m[0]
}

func TestAVerifiedListIsThePolicyAndTheBootstrapIsNotAddedToIt(t *testing.T) {
	f := newListFixture(t)
	t.Setenv("AGENT_ACCEPTED_MEASUREMENTS", aMeasurement(0x77))
	if err := f.submit("seq7"); err != nil {
		t.Fatalf("the publisher's list was refused: %v", err)
	}
	s := f.server(f.lists)
	if !s.acceptableMeasurement(f.measurement("seq7")) {
		t.Error("the listed measurement was refused")
	}
	for _, b := range []byte{0x77, 0x99} {
		if s.acceptableMeasurement(mustHex(t, aMeasurement(b))) {
			t.Errorf("%#x accepted though it is not on the list", b)
		}
	}
}

func TestNoListMeansTheBootstrapAlone(t *testing.T) {
	f := newListFixture(t)
	t.Setenv("AGENT_ACCEPTED_MEASUREMENTS", aMeasurement(0x77))
	if !f.server(f.lists).acceptableMeasurement(mustHex(t, aMeasurement(0x77))) {
		t.Error("the bootstrap was not used")
	}
}

// A list whose witnesses cannot be asked is not used, is not recorded, and
// leaves the bootstrap exactly as it was.
func TestAListWhoseWitnessesCannotBeAskedIsNotUsed(t *testing.T) {
	f := newListFixture(t)
	t.Setenv("AGENT_ACCEPTED_MEASUREMENTS", aMeasurement(0x77))
	f.w.silent = true
	if err := f.submit("seq7"); err == nil || !strings.Contains(err.Error(), anchored.ErrNotFresh.Error()) {
		t.Fatalf("a list nobody vouched for just now: %v", err)
	}
	if _, err := os.Stat(filepath.Join(f.dir, measurementFloorsFile)); err == nil {
		t.Fatal("a floor was recorded for a list that was not accepted")
	}
	s := f.server(f.lists)
	if s.acceptableMeasurement(f.measurement("seq7")) || !s.acceptableMeasurement(mustHex(t, aMeasurement(0x77))) {
		t.Fatal("a refused list changed the policy")
	}
	// witnesses that hold the publisher's state before this bundle: the bundle goes past them
	f.w.silent = false
	f.w.holds = "seq7"
	if _, err := f.lists.check(context.Background(), []byte(f.v.Bundles["seq8"])); err == nil {
		t.Fatal("a bundle past what the witnesses hold was accepted")
	}
}

func TestAnOldListIsNotUsedAfterANewerOne(t *testing.T) {
	f := newListFixture(t)
	t.Setenv("AGENT_ACCEPTED_MEASUREMENTS", aMeasurement(0x77))
	if err := f.submit("seq8"); err != nil {
		t.Fatal(err)
	}
	if err := f.submit("seq7"); err == nil {
		t.Fatal("the older list was accepted after the newer one")
	}
	s := f.server(f.lists)
	if !s.acceptableMeasurement(f.measurement("seq8")) {
		t.Error("the newer list stopped being the policy")
	}
	for _, m := range [][]byte{f.measurement("seq7"), mustHex(t, aMeasurement(0x77))} {
		if s.acceptableMeasurement(m) {
			t.Fatalf("%x accepted after sequence 8", m[len(m)-1])
		}
	}
	// and a core that starts afresh on the same data refuses it too
	f.lists = f.newCore()
	if err := f.submit("seq7"); err == nil {
		t.Fatal("the older list was accepted after a restart")
	}
}

// Once a list has been accepted, none of these may widen to the bootstrap.
func TestOnceAListIsAcceptedNoFailureFallsBackToTheBootstrap(t *testing.T) {
	cases := map[string]func(f *listFixture) time.Time{
		"a restart, not asked again":              func(f *listFixture) time.Time { f.lists = f.newCore(); return f.now },
		"too long since the witnesses were asked": func(f *listFixture) time.Time { return f.now.Add(listFreshFor + time.Minute) },
		"the list expired":                        func(f *listFixture) time.Time { return f.now.Add(70 * 24 * time.Hour) },
		"a clock set back":                        func(f *listFixture) time.Time { return f.now.Add(-time.Hour) },
		"a damaged floor": func(f *listFixture) time.Time {
			os.WriteFile(filepath.Join(f.dir, measurementFloorsFile), []byte("x"), 0o600)
			return f.now
		},
		"the floor deleted, and stale": func(f *listFixture) time.Time {
			os.Remove(filepath.Join(f.dir, measurementFloorsFile))
			return f.now.Add(2 * time.Hour)
		},
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			f := newListFixture(t)
			t.Setenv("AGENT_ACCEPTED_MEASUREMENTS", aMeasurement(0x77))
			if err := f.submit("seq7"); err != nil {
				t.Fatal(err)
			}
			at := breakIt(f)
			m, why, err := f.lists.policy("individual", at)
			if err != nil || len(m) != 0 {
				t.Fatalf("accepted %d measurements, err %v", len(m), err)
			}
			if why == "" {
				t.Fatal("no reason was given for refusing every box")
			}
		})
	}
}

// Asking again refreshes it: the same list, a little later, with the witnesses
// answering, is the policy again.
func TestAskingTheWitnessesAgainKeepsTheListInUse(t *testing.T) {
	f := newListFixture(t)
	if err := f.submit("seq7"); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(2 * time.Hour)
	if m, _, _ := f.lists.policy("individual", f.now); len(m) != 0 {
		t.Fatal("a list not checked for two hours was used")
	}
	if err := f.submit("seq7"); err != nil {
		t.Fatalf("the same list was refused when it was checked again: %v", err)
	}
	if m, why, _ := f.lists.policy("individual", f.now); len(m) != 1 || why != "" {
		t.Fatalf("policy %v, %q", m, why)
	}
}

func TestAVerifiedListThatNamesNothingForThisKindRefusesEverything(t *testing.T) {
	f := newListFixture(t)
	t.Setenv("AGENT_ACCEPTED_MEASUREMENTS", aMeasurement(0x77))
	if err := f.submit("seq7"); err != nil {
		t.Fatal(err)
	}
	m, why, _ := f.lists.policy("organization", f.now) // the list names only "individual"
	if len(m) != 0 {
		t.Fatalf("%d measurements accepted for a kind the list does not name (%q)", len(m), why)
	}
}

func TestABuildThatPinsNoPublisherAcceptsNoList(t *testing.T) {
	f := newListFixture(t)
	f.lists.pin = nil // anchored.Pinned: the ldflags are empty in a test build
	if err := f.submit("seq7"); err == nil || !strings.Contains(err.Error(), anchored.ErrNoPin.Error()) {
		t.Fatalf("a build with no pin accepted a list: %v", err)
	}
}

// The owner's per-adoption statement survives an accepted list, but only adds
// what the owner named: a list that is not in use still refuses everything else.
func TestTheOwnersNamedMeasurementOnlyAddsAndNeverLiftsAListRefusal(t *testing.T) {
	f := newListFixture(t)
	t.Setenv("AGENT_ACCEPTED_MEASUREMENTS", aMeasurement(0x77))
	if err := f.submit("seq8"); err != nil {
		t.Fatal(err)
	}
	f.lists = f.newCore() // a restart: the list must be checked again, and has not been
	s := f.server(f.lists)
	named := [][]byte{mustHex(t, aMeasurement(0x55))}
	accept := s.acceptableOrOwnerNamed(named)
	if !accept(mustHex(t, aMeasurement(0x55))) {
		t.Error("what the owner named was refused")
	}
	for _, m := range [][]byte{f.measurement("seq7"), f.measurement("seq8"), mustHex(t, aMeasurement(0x77))} {
		if accept(m) {
			t.Errorf("%x accepted because the owner named something else", m[len(m)-1])
		}
	}
	if s.acceptableMeasurement(mustHex(t, aMeasurement(0x55))) {
		t.Error("the owner's one-adoption statement leaked into the standing policy")
	}
}

// The route an app calls: the verdict is in words, and only a list that holds is staged.
func TestTheRouteChecksTheBundleWithTheWitnessesAndSaysWhy(t *testing.T) {
	f := newListFixture(t)
	s := f.server(f.lists)
	post := func(body string) (int, map[string]any) {
		rec := httptest.NewRecorder()
		s.handleMeasurementList(rec, ownerRequest(http.MethodPost, "/api/measurement-list", strings.NewReader(body), s))
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	if code, out := post("not a bundle"); code != http.StatusUnprocessableEntity {
		t.Fatalf("garbage: %d %v", code, out)
	}
	f.w.holds, f.w.silent = "seq7", true
	if code, _ := post(f.v.Bundles["seq7"]); code != http.StatusServiceUnavailable {
		t.Fatalf("witnesses silent: %d", code)
	}
	f.w.silent = false
	if code, _ := post(f.v.Bundles["seq8"]); code == http.StatusOK {
		t.Fatal("a bundle past the witnesses' tip was accepted")
	}
	code, out := post(f.v.Bundles["seq7"])
	if code != http.StatusOK || out["sequence"] != float64(7) {
		t.Fatalf("the publisher's list: %d %v", code, out)
	}
	if !s.acceptableMeasurement(f.measurement("seq7")) {
		t.Fatal("an accepted list is not the policy")
	}
	// the witnesses now hold more: the old bundle is behind them
	f.w.holds = "seq8"
	if code, _ := post(f.v.Bundles["seq7"]); code != http.StatusConflict {
		t.Fatalf("a bundle behind the witnesses: %d", code)
	}
	if code, _ := post(f.v.Bundles["seq8"]); code != http.StatusOK {
		t.Fatalf("the newer list: %d", code)
	}
}

func TestEvidenceOfAConflictingHistoryIsKept(t *testing.T) {
	f := newListFixture(t)
	f.lists.recordDuplicity(&anchored.Duplicity{SN: 3, Held: "EHELD", Offered: "EOFFERED", Message: []byte("m")})
	raw, err := os.ReadFile(filepath.Join(f.dir, measurementDuplicityFile))
	if err != nil || !strings.Contains(string(raw), "EOFFERED") || !strings.Contains(string(raw), "EHELD") {
		t.Fatalf("%q %v", raw, err)
	}
}

// A list that expires after it was checked, within the hour it is trusted for,
// stops being used at its own expiry and not at the end of that hour.
func TestAListIsNotUsedPastItsOwnExpiryEvenJustAfterItWasChecked(t *testing.T) {
	f := newListFixture(t)
	expires := f.now.Add(-time.Hour).Add(60 * 24 * time.Hour) // t0 + 60 days: what the vectors' lists say
	f.now = expires.Add(-10 * time.Minute)
	if err := f.submit("seq7"); err != nil {
		t.Fatal(err)
	}
	if m, _, _ := f.lists.policy("individual", expires.Add(-time.Minute)); len(m) != 1 {
		t.Fatal("the list was not used before it expired")
	}
	if m, why, _ := f.lists.policy("individual", expires.Add(time.Minute)); len(m) != 0 || why == "" {
		t.Fatalf("an expired list was used: %v %q", m, why)
	}
}
