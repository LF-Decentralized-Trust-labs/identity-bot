package secureenclave

import "testing"

// A report that permits debug access is refused in production and accepted in a
// development build; a report that does not permit debug is never refused on
// that ground. A development box is run debug-attested on purpose, so a dev
// build must accept exactly what production rejects.
func TestDebugReportRefusedByRealm(t *testing.T) {
	if !DebugReportRefused(true, false) {
		t.Fatal("production must refuse a report that permits debug access")
	}
	if DebugReportRefused(true, true) {
		t.Fatal("a development build must accept a report that permits debug access")
	}
	if DebugReportRefused(false, false) || DebugReportRefused(false, true) {
		t.Fatal("a report that does not permit debug access is never refused on debug grounds")
	}
}
