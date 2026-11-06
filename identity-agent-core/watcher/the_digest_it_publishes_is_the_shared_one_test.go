package watcher

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The watcher publishes whatever digest witnessproto computes, and a peer
// compares its own against that. So the shared vectors must come out of the
// watcher's own path byte for byte, not only out of the function: a second
// digest written beside it, or a change to how the log is serialised, fails
// here as well as in witnessproto.
//
// The vectors are read from where witnessproto keeps them. They are not copied.
func TestTheDigestTheWatcherRecordsIsTheSharedVectorsDigest(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "witnessproto", "kel-digest-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vs []struct {
		Name   string                   `json:"name"`
		Events []map[string]interface{} `json:"events"`
		Seq    int                      `json:"seq"`
		Digest string                   `json:"digest"`
	}
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) < 5 {
		t.Fatalf("only %d vectors; the file has lost cases", len(vs))
	}
	checked := 0
	for _, v := range vs {
		// A vector that stops short of the log's tip is for the function alone:
		// the watcher always digests through the tip.
		if tip := len(v.Events) - 1; v.Seq != tip {
			continue
		}
		ws, _ := migratedWatcher(t)
		res, err := ws.VerifyKel(context.Background(), VerifyKelInput{AID: "E" + v.Name, KEL: v.Events})
		if err != nil {
			t.Errorf("%s: %v", v.Name, err)
			continue
		}
		if res.Digest != v.Digest {
			t.Errorf("%s: the watcher recorded %s, the shared vectors say %s", v.Name, res.Digest, v.Digest)
		}
		rec, _ := ws.Store.GetFirstSeen("E"+v.Name, v.Seq)
		if rec == nil || rec.KelDigest != v.Digest {
			t.Errorf("%s: the stored first-seen digest is not the vectors' digest", v.Name)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no vector reaches its log's tip, so nothing was checked through the watcher")
	}
}
