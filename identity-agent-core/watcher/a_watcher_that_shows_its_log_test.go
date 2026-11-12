package watcher

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/witnessproto"
	"identity-agent-core/drivers"
	"identity-agent-core/drivers/signedlog"
)

// aWatcher is a standing watcher for tests: it answers a signed digest of the log
// it holds, as /public/kel-digest does, and serves that log with its controller
// signatures, as GET /witness/kel/{aid} does.
type aWatcher struct {
	URL string
	// Rival are events it kept at places it already held something else at.
	Rival []map[string]interface{}
	// LogFetches counts requests for its log.
	LogFetches atomic.Int32
	// Hide makes it refuse to show its log.
	Hide atomic.Bool
	// Alter changes the served records on the way out.
	Alter func([]map[string]interface{}) []map[string]interface{}

	records []map[string]interface{}
}

// aWatcherHolding starts a watcher that holds log (nil: it has seen nothing).
func aWatcherHolding(t *testing.T, trusted *testWatcherKey, log *signedlog.Log) *aWatcher {
	t.Helper()
	w := &aWatcher{}
	if log != nil {
		w.records = recordsOf(log)
	}
	var aid string
	if log != nil {
		aid = log.AID
	}
	_, serving := servedBy(t, trusted, nil)
	// A watcher digests the events themselves, as the hosted one does, not the
	// signature and bytes served beside them.
	pure := make([]map[string]interface{}, 0, len(w.records))
	for _, rec := range w.records {
		var ev map[string]interface{}
		if err := json.Unmarshal([]byte(rec["event_json"].(string)), &ev); err != nil {
			t.Fatal(err)
		}
		pure = append(pure, ev)
	}
	for seq := range w.records {
		d, err := witnessproto.KelDigestAtSeq(pure, seq)
		if err != nil {
			t.Fatal(err)
		}
		seen(t, serving, aid, seq, d)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/witness/kel/") {
			w.LogFetches.Add(1)
			if w.Hide.Load() {
				http.Error(rw, "not held", http.StatusNotFound)
				return
			}
			recs := w.records
			if w.Alter != nil {
				recs = w.Alter(recs)
			}
			_ = json.NewEncoder(rw).Encode(map[string]interface{}{"aid": aid, "kel": recs, "conflicting": w.Rival, "count": len(recs)})
			return
		}
		seq := 0
		for _, c := range r.URL.Query().Get("seq") {
			seq = seq*10 + int(c-'0')
		}
		resp, err := serving.GetPublicDigest(r.URL.Query().Get("aid"), seq)
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		_ = json.NewEncoder(rw).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	w.URL = srv.URL
	return w
}

// setStanding makes url the default standing watcher.
func setStanding(ws *Service, url string, more ...string) error {
	if err := ws.Store.SetConfig("default_l2_url", url); err != nil {
		return err
	}
	var extra []StandingWatcher
	for _, u := range more {
		extra = append(extra, StandingWatcher{URL: u})
	}
	return ws.SetStandingWatchers(extra)
}

// presenting is what a route hands the watcher for log.
func presenting(t *testing.T, log *signedlog.Log, source SourceType) VerifyKelInput {
	t.Helper()
	signed, err := drivers.SignedMessagesFromRecords(log.Records())
	if err != nil {
		t.Fatal(err)
	}
	return VerifyKelInput{AID: log.AID, KEL: recordsOf(log), Signed: signed, SourceType: source}
}

// recordsOf is the log as records a route holds: the signed bytes and signature,
// and the event's own fields beside them (sequence number, digest, ...).
func recordsOf(log *signedlog.Log) []map[string]interface{} {
	recs := log.Records()
	for _, rec := range recs {
		var ev map[string]interface{}
		if err := json.Unmarshal([]byte(rec["event_json"].(string)), &ev); err == nil {
			for k, v := range ev {
				if _, taken := rec[k]; !taken {
					rec[k] = v
				}
			}
		}
	}
	return recs
}
