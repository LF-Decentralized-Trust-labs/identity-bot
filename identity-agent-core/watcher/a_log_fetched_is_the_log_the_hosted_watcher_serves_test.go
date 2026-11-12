package watcher

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	keri "github.com/grapeid/keri-go"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/witnessproto"
	"identity-agent-core/drivers"
)

// The contract between this client's FetchLog and a watcher service's
// GET /witness/kel/{aid}: one committed fixture (witnessproto.KelLogContractFixture)
// that the hosted watcher tests its serving against too, so neither side is
// tested against a fake it wrote for itself. The identity has three keys and
// signs every event with two of them; a second validly signed event is held
// beside the first at place 2.
func TestFetchLogReadsExactlyWhatTheSharedFixtureServes(t *testing.T) {
	c, err := witnessproto.ReadKelLogContract()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(c.Served)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/witness/kel/"+c.AID) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	got, err := (&L2Client{HTTPClient: http.DefaultClient}).FetchLog(context.Background(), srv.URL+"/public/kel-digest", c.AID)
	if err != nil {
		t.Fatalf("FetchLog: %v", err)
	}
	if len(got.Messages) != c.Served.Count || len(got.Rival) != 1 {
		t.Fatalf("read %d events and %d rivals, the fixture serves %d and 1", len(got.Messages), len(got.Rival), c.Served.Count)
	}
	// Every signature the watcher served is in the message, so a threshold of
	// several is judged as it was signed; one signature per event would fail it.
	v, err := keri.ValidateSignedKEL(got.Messages)
	if err != nil {
		t.Fatalf("the log the fixture serves does not verify as read: %v", err)
	}
	if v.Identifier != c.AID || v.Events != c.Served.Count {
		t.Fatalf("read %s with %d events", v.Identifier, v.Events)
	}
	for i, m := range got.Messages {
		want, _ := base64.StdEncoding.DecodeString(c.Submissions[i].EventB64)
		if !strings.HasPrefix(string(m), string(want)) {
			t.Fatalf("event %d is not the event the fixture was published as", i)
		}
	}
	// Records come back in the shape callers hold, signatures included.
	if sigs := drivers.RecordSignatures(got.Records[0]); len(sigs) != 2 {
		t.Fatalf("the records lost a signature: %d", len(sigs))
	}

	// The rival beside the held log is a second history at place 2, and the held
	// log beside the rival is the same: proof of duplicity either way round,
	// whose evidence re-verifies from what it stores.
	rivalBranch := append(append([][]byte(nil), got.Messages[:c.RivalSeq]...), got.Rival[0])
	for name, p := range map[string]proof{
		"the held log presented, the rival served beside it": judgeWatcherLog(c.AID, got.Messages, &WatcherLog{Messages: got.Messages, Rival: got.Rival}),
		"the rival branch presented, the held log served":    judgeWatcherLog(c.AID, rivalBranch, &WatcherLog{Messages: got.Messages}),
	} {
		if p.Kind != proofFork || p.Evidence == nil {
			t.Fatalf("%s: %v %s", name, p.Kind, p.Reason)
		}
		if err := p.Evidence.Reverify(); err != nil {
			t.Fatalf("%s: the evidence does not re-verify: %v", name, err)
		}
	}

	// The digests the fixture says a watcher answers are the ones this side computes.
	var events []map[string]interface{}
	for _, rec := range got.Records {
		raw, _ := drivers.DecodeRawBytes(rec["raw_bytes_b64"].(string))
		var f map[string]interface{}
		if err := json.Unmarshal(raw, &f); err != nil {
			t.Fatal(err)
		}
		events = append(events, f)
	}
	for _, d := range c.Digests {
		if got, err := witnessproto.KelDigestAtSeq(events, d.Seq); err != nil || got != d.Digest {
			t.Fatalf("digest at %d: %q %v, fixture %q", d.Seq, got, err, d.Digest)
		}
	}
}
