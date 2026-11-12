package measurementlist

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"time"

	"identity-agent-core/atomicfile"
)

// LoadFile verifies the list at path and, if it passes, records its sequence
// and content hash in floorPath so an older list, or different content at the
// same sequence, is refused from then on.
//
// The floor is what makes "an old list" a refusal across restarts: without it
// a stale copy put back on disk would verify, because its signature is as
// good as the day it was made. A floor that exists but cannot be read is an
// error, never zero — reading damage as "nothing seen yet" would reopen
// exactly that.
//
// The record is one line, "<sequence> <sha256 of the signed bytes, hex>". A
// bare "<sequence>" (written by an earlier version) is still read; the hash
// is then recorded the next time that same sequence is accepted.
//
// What guards what: the floor stops a rollback of the list. It does not stop
// the clock being set back (a list is "expired" only by this machine's time),
// so an expired list is also refused on the strength of its own dates, and a
// clock set back never lowers the floor. Deleting the floor AND the list
// together returns the agent to "no list ever accepted" and so to the
// bootstrap; that is the one remaining attack, which is why the floor is
// written 0600 in the agent's own data directory, where the writer of the
// list file has no reason to reach.
func LoadFile(path, floorPath string, key PinnedKey, now time.Time) (*List, error) {
	floor, seen, err := ReadFloor(floorPath)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the measurement list: %w", err)
	}
	l, err := Verify(raw, Policy{Key: key, MinSequence: floor, SeenDigest: seen, Now: now})
	if err != nil {
		return nil, err
	}
	if l.Sequence > floor || seen == "" {
		rec := strconv.FormatInt(l.Sequence, 10) + " " + l.Digest + "\n"
		if err := atomicfile.Write(floorPath, []byte(rec), 0o600); err != nil {
			// Not recorded means a later rollback would not be caught, so the
			// list is not used on the strength of a floor that did not stick.
			return nil, fmt.Errorf("recording the list's sequence: %w", err)
		}
	}
	return l, nil
}

// ReadFloor returns the highest accepted sequence (0 if none was ever
// accepted) and the hash of the list accepted at it ("" if not recorded).
func ReadFloor(path string) (int64, string, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, "", nil
	}
	if err != nil {
		return 0, "", fmt.Errorf("reading the accepted-sequence record: %w", err)
	}
	damaged := fmt.Errorf("the accepted-sequence record %s is damaged; refusing every list until it is restored or removed by hand", path)
	f := strings.Fields(string(b))
	if len(f) < 1 || len(f) > 2 {
		return 0, "", damaged
	}
	n, err := strconv.ParseInt(f[0], 10, 64)
	if err != nil || n < 0 {
		return 0, "", damaged
	}
	digest := ""
	if len(f) == 2 {
		if !isHex(f[1], 32) {
			return 0, "", damaged
		}
		digest = f[1]
	}
	return n, digest, nil
}
