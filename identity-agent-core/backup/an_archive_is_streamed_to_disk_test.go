package backup

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A destination that can stream. Pull is a failure on purpose: a fetch that
// falls back to it has held the whole archive in memory.
type streamingBackend struct {
	*mockRemoteBackend
	t        *testing.T
	chunk    int
	midway   func() // run after the first chunk, while the download is still going
	streamed bool
}

func (b *streamingBackend) Pull(ctx context.Context, key string) ([]byte, error) {
	b.t.Error("the whole archive was pulled into memory instead of streamed")
	return nil, fmt.Errorf("pulled whole")
}

func (b *streamingBackend) PullTo(ctx context.Context, key string, w io.Writer) error {
	b.streamed = true
	b.mockRemoteBackend.mu.Lock()
	data := b.mockRemoteBackend.files[key]
	b.mockRemoteBackend.mu.Unlock()
	for off := 0; off < len(data); off += b.chunk {
		end := min(off+b.chunk, len(data))
		if _, err := w.Write(data[off:end]); err != nil {
			return err
		}
		if off == 0 && b.midway != nil {
			b.midway()
		}
	}
	return nil
}

func aStreamingDestination(t *testing.T, midway func(dir string)) (*Service, Destination, *streamingBackend, []byte) {
	t.Helper()
	svc := NewService(t.TempDir(), nil)
	credID, err := svc.SaveDestinationCredentials(RemoteCredentialSecrets{AccessKey: "k", SecretKey: "s"})
	if err != nil {
		t.Fatal(err)
	}
	archive := bytes.Repeat([]byte("0123456789abcdef"), 1024) // 16 KiB, several chunks
	be := &streamingBackend{
		mockRemoteBackend: &mockRemoteBackend{files: map[string][]byte{"aid/backup-full-20261101-000000.iab": archive}},
		t:                 t,
		chunk:             1024,
	}
	if midway != nil {
		be.midway = func() {
			dirs, _ := filepath.Glob(filepath.Join(svc.DataDir, RestoringPrefix+"fetch-*"))
			if len(dirs) != 1 {
				t.Errorf("expected one working directory during the download, found %v", dirs)
				return
			}
			midway(dirs[0])
		}
	}
	orig := remoteBackendFactory
	remoteBackendFactory = func(Destination, RemoteCredentialSecrets) (remoteBackend, error) { return be, nil }
	t.Cleanup(func() { remoteBackendFactory = orig })
	dest := Destination{ID: "c", Type: DestCloudUser, Enabled: true, CloudProvider: "s3",
		CloudBucket: "b", CloudPrefix: "aid", CredentialID: credID}
	return svc, dest, be, archive
}

// A backend that can stream is streamed: the archive reaches the file in
// pieces and is never pulled whole. Fails if the archiveStreamer branch is
// removed (the fallback calls Pull, which fails the test).
func TestAnArchiveFromABackendThatCanStreamIsNeverHeldWhole(t *testing.T) {
	svc, dest, be, archive := aStreamingDestination(t, nil)
	path, _, size, done, err := svc.PullLatestArchiveToFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	if !be.streamed {
		t.Fatal("PullTo was not used")
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, archive) || size != int64(len(archive)) {
		t.Fatal("what was streamed to disk is not the archive")
	}
}

// The directory a download writes into is marked in use, so the sweep another
// start of the core runs on a directory that has sat untouched for hours (a
// download of a gigabyte can) does not take it from under the download.
// Fails if PullLatestArchiveToFile does not call InUse.
func TestADownloadInProgressIsNotSweptAway(t *testing.T) {
	var svcRef *Service
	var swept bool
	svc, dest, _, archive := aStreamingDestination(t, func(dir string) {
		old := time.Now().Add(-3 * abandonedAfter)
		if err := os.Chtimes(dir, old, old); err != nil {
			t.Error(err)
		}
		SweepUpAbandoned(svcRef.DataDir)
		swept = true
		if _, err := os.Stat(dir); err != nil {
			t.Errorf("the sweep took the working directory of a download still going: %v", err)
		}
	})
	svcRef = svc
	path, _, _, done, err := svc.PullLatestArchiveToFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !swept {
		t.Fatal("the sweep never ran")
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, archive) {
		t.Fatal("the archive did not survive the sweep")
	}

	dir := filepath.Dir(path)
	if !isInUse(dir) {
		t.Fatal("the directory should still be in use until done")
	}
	done()
	if isInUse(dir) {
		t.Fatal("done left the directory marked in use")
	}
}
