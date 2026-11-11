package recovery

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"

	"identity-agent-core/atomicfile"
	"identity-agent-core/drivers"
	"identity-agent-core/store"
)

// A break-glass run stopped part way is finished by sending the same signed
// request again (RotateRootAID). The app may have lost its copy by then, and
// the only other thing it can do is prepare and sign a second run after the
// rotation the first already added, which leaves two roots the old root's log
// authorises. So the core keeps the signed request from the moment the first
// event of a run lands, keyed by the old root, until the run completes, and
// offers it back to the owner.

const rootAIDRunsDirName = "root_aid_runs"

// RunningRootAIDRotation is a signed request whose run has begun and not
// finished.
type RunningRootAIDRotation struct {
	OldRootAID string                 `json:"old_root_aid"`
	NewRootAID string                 `json:"new_root_aid"`
	Request    RootAIDRotationRequest `json:"request"`
}

var (
	rootAIDRunsMu sync.Mutex
	// An identifier is base64url; anything else is not a file name to trust.
	identifierRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
)

func rootAIDRunPath(dataDir, oldRootAID string) (string, error) {
	if dataDir == "" {
		return "", fmt.Errorf("data directory is required")
	}
	if !identifierRE.MatchString(oldRootAID) {
		return "", fmt.Errorf("%q is not an identifier", oldRootAID)
	}
	return filepath.Join(dataDir, rootAIDRunsDirName, oldRootAID+".json"), nil
}

// keepRunningRootAIDRotation records the run, replacing any earlier run of the
// same old root.
func keepRunningRootAIDRotation(dataDir string, run RunningRootAIDRotation) error {
	path, err := rootAIDRunPath(dataDir, run.OldRootAID)
	if err != nil {
		return err
	}
	body, err := json.Marshal(run)
	if err != nil {
		return err
	}
	rootAIDRunsMu.Lock()
	defer rootAIDRunsMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("keep the running rotation: %w", err)
	}
	// Flushed, then renamed: a crash leaves the old request or this one, and
	// the signed request is the only way to finish a half-done rotation.
	if err := atomicfile.Write(path, body, 0o600); err != nil {
		return fmt.Errorf("keep the running rotation: %w", err)
	}
	return nil
}

// forgetRunningRootAIDRotation removes the run once it is complete.
func forgetRunningRootAIDRotation(dataDir, oldRootAID string) error {
	path, err := rootAIDRunPath(dataDir, oldRootAID)
	if err != nil {
		return err
	}
	rootAIDRunsMu.Lock()
	defer rootAIDRunsMu.Unlock()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("forget the running rotation: %w", err)
	}
	return nil
}

// RunningRootAIDRotations are the runs begun and not finished, by old root.
func RunningRootAIDRotations(dataDir string) ([]RunningRootAIDRotation, error) {
	if dataDir == "" {
		return nil, nil
	}
	rootAIDRunsMu.Lock()
	defer rootAIDRunsMu.Unlock()
	entries, err := os.ReadDir(filepath.Join(dataDir, rootAIDRunsDirName))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []RunningRootAIDRotation
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dataDir, rootAIDRunsDirName, e.Name()))
		if err != nil {
			return nil, err
		}
		var run RunningRootAIDRotation
		if err := json.Unmarshal(body, &run); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		out = append(out, run)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].OldRootAID < out[j].OldRootAID })
	return out, nil
}

// UnfinishedRootAIDRotation is the run begun and not finished that has aid as
// its old root or its new root, if there is one: the identity kept here is the
// old root before the run moves it and the new root after.
func UnfinishedRootAIDRotation(dataDir, aid string) (*RunningRootAIDRotation, error) {
	runs, err := RunningRootAIDRotations(dataDir)
	if err != nil {
		return nil, err
	}
	for i := range runs {
		if runs[i].OldRootAID == aid || runs[i].NewRootAID == aid {
			return &runs[i], nil
		}
	}
	return nil, nil
}

// RotationLanded reports whether the run's old-root rotation is in the old
// root's stored log. Until it is, the run has authorised nothing (at most the
// new root's founding is stored, which nothing points to), so it may be
// dropped and another prepared; once it is, the old root's log authorises this
// run's new root and only finishing this run is safe.
//
// It compares the events' digests, not their base64: the same bytes have more
// than one base64 spelling (a decoder ignores line breaks), and a run judged
// not landed when it had would let a second run leave two roots. An event that
// cannot be read is taken as landed, so a doubt keeps the run rather than
// dropping it.
func (run RunningRootAIDRotation) RotationLanded(events []store.EventRecord) bool {
	said, ok := saidOfB64(run.Request.OldRootRotation.RawB64)
	if !ok {
		return true
	}
	for _, ev := range events {
		if held, ok := saidOfB64(ev.RawBytesB64); ok && held == said {
			return true
		}
	}
	return false
}

func saidOfB64(b64 string) (string, bool) {
	said, _ := drivers.EventIDOfRawB64(b64)
	return said, said != ""
}

// DropUnfinishedRootAIDRotation forgets a run whose rotation has not landed.
func DropUnfinishedRootAIDRotation(dataDir string, run RunningRootAIDRotation) error {
	return forgetRunningRootAIDRotation(dataDir, run.OldRootAID)
}
