package recovery

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"identity-agent-core/backup"
)

// An archive fetched from a destination is kept on disk and named by a
// reference, never carried to the app as base64 inside JSON.
//
// It used to be read whole, base64-encoded, put in a JSON body, and sent back by
// the app inside two more: the archive in memory several times over, which for a
// gigabyte ends a phone's process. Now it is streamed to a file in one of this
// agent's own working directories, and the app is given a reference to it that
// Verify and Start accept in place of archive_b64.
//
// A reference is NOT a path. It names an entry in a table this agent keeps in
// memory, made only by a fetch this agent did itself, so it cannot be made to
// point at any other file — which is what removing the old path input was for.

// maxFetched bounds how many fetched archives are kept at once.
const maxFetched = 2

type fetchedArchive struct {
	path      string
	objectKey string
	made      time.Time
	done      func()
}

// keepFetched records a fetched archive and returns its reference.
func (s *Service) keepFetched(path, objectKey string, done func()) string {
	s.fetchedMu.Lock()
	defer s.fetchedMu.Unlock()
	if s.fetched == nil {
		s.fetched = map[string]*fetchedArchive{}
	}
	var oldest string
	for ref, f := range s.fetched {
		if len(s.fetched) >= maxFetched && (oldest == "" || f.made.Before(s.fetched[oldest].made)) {
			oldest = ref
		}
	}
	if oldest != "" {
		s.fetched[oldest].done()
		delete(s.fetched, oldest)
	}
	ref := filepath.Base(filepath.Dir(path))
	s.fetched[ref] = &fetchedArchive{path: path, objectKey: objectKey, made: time.Now(), done: done}
	return ref
}

// archiveFrom resolves what a request names: the archive itself, or a reference
// to one this agent fetched. It also returns the name the archive had in the
// destination it came from, when it came from one.
func (s *Service) archiveFrom(archiveB64, ref, name string) (raw []byte, objectKey string, err error) {
	if ref == "" {
		raw, err = decodeArchiveInput(archiveB64)
		return raw, name, err
	}
	if archiveB64 != "" {
		return nil, "", fmt.Errorf("give archive_b64 or archive_ref, not both")
	}
	s.fetchedMu.Lock()
	f, ok := s.fetched[ref]
	s.fetchedMu.Unlock()
	if !ok || !strings.HasPrefix(ref, backup.RestoringPrefix) {
		return nil, "", fmt.Errorf("that fetched archive is gone; fetch it again")
	}
	raw, err = os.ReadFile(f.path)
	return raw, f.objectKey, err
}

// finishedWith removes a fetched archive once nothing needs it.
func (s *Service) finishedWith(ref string) {
	if ref == "" {
		return
	}
	s.fetchedMu.Lock()
	f, ok := s.fetched[ref]
	delete(s.fetched, ref)
	s.fetchedMu.Unlock()
	if ok {
		f.done()
	}
}

// whenItWasMade says when the archive was made — from inside the authenticated
// archive, not from the name it was stored under — and what to warn about.
// Remembers it, so an older one opened later is noticed.
func (s *Service) whenItWasMade(createdAt, objectKey string) (string, []string) {
	if s.BackupService == nil || s.BackupService.ConfigStore == nil {
		return createdAt, backup.ArchiveFreshnessWarnings(createdAt, objectKey, time.Time{})
	}
	cs := s.BackupService.ConfigStore
	warnings := backup.ArchiveFreshnessWarnings(createdAt, objectKey, cs.NewestArchiveSeen())
	cs.NoteArchiveSeen(createdAt)
	return createdAt, warnings
}
