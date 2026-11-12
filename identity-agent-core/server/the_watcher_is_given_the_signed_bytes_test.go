package server

import (
	"testing"

	"identity-agent-core/drivers/signedlog"
	"identity-agent-core/watcher"
)

// Whatever route reaches the watcher (OOBI resolve, add-contact, both
// credential-issuer checks, sign-in), runWatcherOnKel is the one place that
// builds its input, so the log's signed bytes ride along there.
func TestTheWatcherInputCarriesTheLogsSignedBytes(t *testing.T) {
	l := signedlog.Incept(t, signedlog.NewKeys(t, 2)).Rotate()
	in := watcherInputFor(l.AID, l.Records(), watcher.SourceOOBI, "", nil)
	if len(in.Signed) != 2 || in.NotSigned != "" {
		t.Fatalf("signed=%d notSigned=%q", len(in.Signed), in.NotSigned)
	}
	recs := l.Records()
	delete(recs[1], "raw_bytes_b64")
	in = watcherInputFor(l.AID, recs, watcher.SourceCredential, "", nil)
	if len(in.Signed) != 0 || in.NotSigned == "" {
		t.Fatalf("a parsed-only log must say so: signed=%d notSigned=%q", len(in.Signed), in.NotSigned)
	}
}
