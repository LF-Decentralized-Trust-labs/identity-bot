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
// in floorPath so an older list is refused from then on.
//
// The floor is what makes "an old list" a refusal across restarts: without it
// a stale copy put back on disk would verify, because its signature is as
// good as the day it was made. A floor that exists but cannot be read is an
// error, never zero — reading damage as "nothing seen yet" would reopen
// exactly that.
func LoadFile(path, floorPath string, key PinnedKey, now time.Time) (*List, error) {
	floor, err := readFloor(floorPath)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the measurement list: %w", err)
	}
	l, err := Verify(raw, Policy{Key: key, MinSequence: floor, Now: now})
	if err != nil {
		return nil, err
	}
	if l.Sequence > floor {
		if err := atomicfile.Write(floorPath, []byte(strconv.FormatInt(l.Sequence, 10)+"\n"), 0o600); err != nil {
			// Not recorded means a later rollback would not be caught, so the
			// list is not used on the strength of a floor that did not stick.
			return nil, fmt.Errorf("recording the list's sequence: %w", err)
		}
	}
	return l, nil
}

func readFloor(path string) (int64, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("reading the accepted-sequence record: %w", err)
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("the accepted-sequence record %s is damaged; refusing every list until it is restored or removed by hand", path)
	}
	return n, nil
}
