package recovery

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// A recovery session has to survive being waited out.
//
// Recovery imposes a cancel window — a day at minimum, two by default — before
// it can complete. That window exists so somebody who did not start the
// recovery has time to stop it. Sessions were held in a map in memory, so any
// restart of the agent lost them: a session could not outlive the wait it was
// required to sit out, and over two days a restart is the expected case rather
// than the exception. The feature could not complete by construction.
//
// What is written down, and what is deliberately not:
//
//   - The session itself — identifiers, timestamps, state. Not secret.
//   - The archive, which is ciphertext this agent cannot open without the
//     phrase. Storing it is what makes resuming possible at all.
//   - NOT the recovery phrase. It arrived once, it opens everything, and
//     writing it to disk for two days to save somebody typing it again would
//     put the identity in the one place the wait is meant to protect.
//   - NOT the decrypted payload, for the same reason: it is the identity in
//     the clear.
//
// So the phrase is supplied again at the end. That is not a gap in the design;
// after a two-day wait it re-proves the person completing the recovery is the
// one who started it, which is the question the wait exists to ask.
type persistedSession struct {
	Session Session `json:"session"`
	// ArchiveB64 is the sealed archive, exactly as it arrived.
	ArchiveB64 string `json:"archive_b64,omitempty"`
	WrittenAt  string `json:"written_at"`
}

// sessionsDir is where sessions wait out their window.
func (s *Service) sessionsDir() string {
	return filepath.Join(s.DataDir, "recovery_sessions")
}

// sessionMaxAge bounds how long a session waits before it is forgotten.
//
// Long enough that no legitimate window comes close — the longest is three
// days — and short enough that an abandoned recovery does not leave somebody's
// sealed archive on disk indefinitely.
const sessionMaxAge = 30 * 24 * time.Hour

// partialSuffix marks a session file still being written.
const partialSuffix = ".partial"

// acceptableSessionID is the same allowlist reasoning used elsewhere: the id is
// a UUID we minted, it becomes a filename, and the characters that make path
// traversal possible are not in the set.
func acceptableSessionID(id string) error {
	if len(id) != 36 {
		return fmt.Errorf("not a session id")
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		ok := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
			(c >= 'A' && c <= 'F') || c == '-'
		if !ok {
			return fmt.Errorf("not a session id")
		}
	}
	return nil
}

// writeSession records a session so it can be picked up after a restart.
func (s *Service) writeSession(rec *sessionRecord) error {
	if err := acceptableSessionID(rec.Session.ID); err != nil {
		return err
	}
	if err := os.MkdirAll(s.sessionsDir(), 0700); err != nil {
		return err
	}
	p := persistedSession{
		Session:   rec.Session,
		WrittenAt: time.Now().UTC().Format(time.RFC3339),
	}
	if len(rec.Archive) > 0 {
		p.ArchiveB64 = base64.StdEncoding.EncodeToString(rec.Archive)
	}
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	// Abandoned sessions are swept whenever one is written, so an always-on
	// agent does not accumulate other people's sealed archives.
	s.ForgetExpiredSessions()
	path := filepath.Join(s.sessionsDir(), rec.Session.ID+".json")
	tmp := path + partialSuffix
	// Written aside, flushed, and renamed. The rename makes the swap atomic;
	// the flush is what makes it mean anything. Without it a power loss can
	// leave a zero-length file, which for a feature whose entire point is
	// surviving an abrupt stop is the case that matters.
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(body); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	// The directory entry too, or the rename itself can be lost.
	if d, derr := os.Open(s.sessionsDir()); derr == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// forgetSession removes a session that has finished or been abandoned.
func (s *Service) forgetSession(id string) {
	if acceptableSessionID(id) != nil {
		return
	}
	p := filepath.Join(s.sessionsDir(), id+".json")
	// Said out loud when it fails. "The archive is deleted once the recovery
	// completes" is a claim about somebody's sealed identity, and a silent
	// failure leaves it on disk while the claim stands.
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		log.Printf("[recovery] could not remove the archive for session %s, so it is still on disk: %v", id, err)
	}
	os.Remove(p + partialSuffix)
}

// ForgetExpiredSessions drops sessions that were abandoned.
//
// Called whenever a session is written, rather than only at startup. Expiry
// used to run inside LoadSessions alone, and that runs once in the life of a
// process — so on an always-on agent an abandoned recovery was never cleaned
// and its sealed archive stayed on disk for as long as the agent ran.
func (s *Service) ForgetExpiredSessions() int {
	entries, err := os.ReadDir(s.sessionsDir())
	if err != nil {
		return 0
	}
	dropped := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Leftovers from a write that died. Skipped when loading, so they only
		// accumulated.
		if strings.HasSuffix(name, partialSuffix) {
			if info, ierr := e.Info(); ierr == nil && time.Since(info.ModTime()) > time.Hour {
				os.Remove(filepath.Join(s.sessionsDir(), name))
			}
			continue
		}
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		body, rerr := os.ReadFile(filepath.Join(s.sessionsDir(), name))
		if rerr != nil {
			continue
		}
		var p persistedSession
		if json.Unmarshal(body, &p) != nil {
			continue
		}
		written, perr := time.Parse(time.RFC3339, p.WrittenAt)
		if perr != nil || time.Since(written) <= sessionMaxAge {
			continue
		}
		s.mu.Lock()
		delete(s.sessions, p.Session.ID)
		s.mu.Unlock()
		s.Rotation.Forget(p.Session.ID)
		os.Remove(filepath.Join(s.sessionsDir(), name))
		dropped++
	}
	return dropped
}

// LoadSessions brings back the sessions that were waiting when this agent last
// stopped.
//
// Called at startup. A session that cannot be read is dropped rather than
// failing the load: one unreadable file must not take out every other recovery
// in progress.
func (s *Service) LoadSessions() (int, error) {
	entries, err := os.ReadDir(s.sessionsDir())
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	loaded := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.sessionsDir(), e.Name())
		body, rerr := os.ReadFile(path)
		if rerr != nil {
			continue
		}
		var p persistedSession
		if json.Unmarshal(body, &p) != nil {
			continue
		}
		if acceptableSessionID(p.Session.ID) != nil {
			continue
		}
		if written, perr := time.Parse(time.RFC3339, p.WrittenAt); perr == nil {
			if time.Since(written) > sessionMaxAge {
				os.Remove(path)
				continue
			}
		}
		// A session already live in memory is the newer record. Loading over it
		// would replace a rotation that has just been done with the disk copy
		// from before it.
		s.mu.Lock()
		_, live := s.sessions[p.Session.ID]
		s.mu.Unlock()
		if live {
			continue
		}
		rec := &sessionRecord{Session: p.Session}
		if p.ArchiveB64 != "" {
			if raw, derr := decodeArchiveInput(p.ArchiveB64); derr == nil {
				rec.Archive = raw
			}
		}
		s.mu.Lock()
		s.sessions[p.Session.ID] = rec
		s.mu.Unlock()
		// The rotation tracker is a cache of what the session records, so it is
		// rebuilt here. Without this a session came back having forgotten that
		// its mandatory rotation was done, and asked for it again.
		if p.Session.RotationDone {
			s.Rotation.MarkCompleted(p.Session.ID, RotationResult{RotatedAt: p.WrittenAt})
		}
		loaded++
	}
	return loaded, nil
}

// InProgress lists the recoveries this agent is holding.
//
// Without this a recovery is reachable only through the screen that started
// it. The wait is measured in days and was deliberately made to survive the
// agent restarting — but a person who pressed back, or closed the app, had no
// way to reach the session again: the id lived in a widget and there was no
// route to rediscover it. The recovery could then be neither finished nor
// stopped, while the agent kept it alive and waiting.
//
// That defeats both halves of what the wait is for. The owner cannot finish,
// and the person who did NOT start it cannot stop it.
func (s *Service) InProgress() []Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Session, 0, len(s.sessions))
	for _, rec := range s.sessions {
		sess := rec.Session
		// The same reading GetSession gives, so a list and a detail view cannot
		// disagree about what state something is in.
		switch sess.State {
		case SessionActivated, SessionFailed, SessionCancelled:
		default:
			if sess.RotationDone {
				sess.State = SessionRotated
			} else if s.CancelGate.Remaining(parseTime(sess.CompleteAfter)) > 0 {
				sess.State = SessionPending
			}
		}
		out = append(out, sess)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt < out[j].StartedAt })
	return out
}
