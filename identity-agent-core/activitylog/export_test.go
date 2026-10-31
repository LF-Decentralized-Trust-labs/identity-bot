package activitylog

import "testing"

// newTestLog is a log in a fresh directory, closed when the test ends.
func newTestLog(t *testing.T) *Log {
	t.Helper()
	l, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open the activity log: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

// For the tests in activitylog_test.
var (
	NewTestLog    = newTestLog
	EventJSON     = (*Log).eventJSON
	WithValidUTF8 = withValidUTF8
)
