package server

import (
	"net"
	"net/http"
	"testing"
	"time"

	"identity-agent-core/activitylog"
	"identity-agent-core/permission"
)

// A request under way when the server is stopped finishes, and what it writes
// to the activity log is kept: Stop lets the servers drain before the log
// closes, rather than closing it beneath the handler.
func TestStopKeepsWhatARequestUnderWayWritesToTheActivityLog(t *testing.T) {
	s := agentWithNoIdentity(t)
	al, err := activitylog.Open(s.DataDir)
	if err != nil {
		t.Skipf("activity log unavailable: %v", err)
	}
	s.ActivityLog = al
	s.running = true

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	arrived, release := make(chan struct{}), make(chan struct{})
	wrote := make(chan int64, 1)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(arrived)
		<-release
		wrote <- al.RecordGovernanceEvent(permission.CallerContext{CallerAID: "ECaller"}, "test.request.finished", "ok")
		w.WriteHeader(http.StatusOK)
	})}
	s.httpSrv, s.listener = srv, ln
	go srv.Serve(ln)

	client := make(chan error, 1)
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String() + "/")
		if err == nil {
			resp.Body.Close()
		}
		client <- err
	}()
	<-arrived

	stopped := make(chan struct{})
	go func() { s.Stop(); close(stopped) }()
	// Stop is draining, so it has not returned and the log is still open.
	select {
	case <-stopped:
		t.Fatal("Stop returned while a request was still under way")
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	select {
	case <-stopped:
	case <-time.After(20 * time.Second):
		t.Fatal("Stop did not return")
	}

	if id := <-wrote; id <= 0 {
		t.Fatalf("the request's write to the activity log was refused (id %d)", id)
	}
	if err := <-client; err != nil {
		t.Fatalf("the request under way did not complete: %v", err)
	}
	// Reopened, the record is there.
	again, err := activitylog.Open(s.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	rows, err := again.QueryInvocationEvents(activitylog.InvocationEventFilter{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rows {
		if r.CapabilityID == "test.request.finished" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the activity log has no record of the request (%d rows)", len(rows))
	}
}
