package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"time"

	"identity-agent-core/internal/atomicfile"
	"identity-agent-core/internal/coretypes"
)

// errRecordUnreadable is a record this Identity Agent keeps in its data
// directory that is there and cannot be read. It is the Identity Agent's
// fault, not the caller's.
var errRecordUnreadable = errors.New("a record this Identity Agent keeps cannot be read")

// readKeptRecord reads the JSON record at path into v.
//
// found is false only when there is no file, which means there is no record
// yet. A file that is there and cannot be read or parsed is an error wrapping
// kind, and is never taken for no record. Each of these records was read as
// empty when it could not be parsed, and the next save wrote a fresh one over
// it: the peers list, the messaging keys, the record identity and the
// witnessing key each went that way, with nothing said. So the file is left
// exactly as it is, and the log says what it is, what cannot work meanwhile,
// and to restore it from a backup. Callers must not write over it.
//
// what names the record for a person; meanwhile says what cannot work until
// it is restored.
func readKeptRecord(path, what, meanwhile string, kind error, v any) (found bool, err error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err == nil {
		err = json.Unmarshal(b, v)
	}
	if err != nil {
		log.Printf("[store] ERROR: %s (%s) cannot be read (%v). It has been left exactly as it "+
			"is and nothing will be written over it. Restore it from a backup; until then %s.",
			what, path, err, meanwhile)
		// The error carries no path. It travels to callers that answer
		// HTTP requests, some of them from anybody, and the data
		// directory's path names the account it lives under. The log
		// above has it.
		cause := err
		var pathErr *fs.PathError
		if errors.As(err, &pathErr) {
			cause = pathErr.Err
		}
		return false, fmt.Errorf("%w: %s cannot be read (%v); restore it from a backup", kind, what, cause)
	}
	return true, nil
}

// statusForUnreadable is the HTTP status for err: 503 when this Identity
// Agent cannot read its own keys or records right now, which is its fault and
// not the caller's, and otherwise for any other error.
func statusForUnreadable(err error, otherwise int) int {
	if errors.Is(err, coretypes.ErrKeysUnavailable) || errors.Is(err, errRecordUnreadable) {
		return http.StatusServiceUnavailable
	}
	return otherwise
}

// staleTemporaryAge is how long a temporary must have sat untouched before
// it is taken for the leftover of a write that stopped. A write takes
// milliseconds; this is generous so that one in flight from another process
// sharing the data directory is never touched.
const staleTemporaryAge = 10 * time.Minute

// removeStaleTemporaries clears what writes that stopped part way left in the
// data directory, at every depth. Each is a whole or partial copy of a record,
// some of them private key material, and nothing else would ever remove them.
func (s *CoreServer) removeStaleTemporaries() {
	if s.DataDir == "" {
		return
	}
	removed, err := atomicfile.RemoveStale(s.DataDir, staleTemporaryAge)
	for _, p := range removed {
		log.Printf("[store] removed %s, left by a write that stopped part way", p)
	}
	if err != nil {
		log.Printf("[store] could not finish clearing what stopped writes left behind: %v", err)
	}
}
