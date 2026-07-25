package drivers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIsTruthy(t *testing.T) {
	for _, v := range []string{"1", "true", "TRUE", "True", "yes", "on"} {
		if !isTruthy(v) {
			t.Errorf("isTruthy(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"", "0", "false", "no", "off", "maybe"} {
		if isTruthy(v) {
			t.Errorf("isTruthy(%q) = true, want false", v)
		}
	}
}

func TestDriverReadyTimeout(t *testing.T) {
	t.Setenv("KERI_DRIVER_READY_TIMEOUT", "")
	if got := driverReadyTimeout(); got != 30*time.Second {
		t.Errorf("default timeout = %s, want 30s", got)
	}
	t.Setenv("KERI_DRIVER_READY_TIMEOUT", "5")
	if got := driverReadyTimeout(); got != 5*time.Second {
		t.Errorf("override timeout = %s, want 5s", got)
	}
	// A bogus value falls back to the default rather than a zero/negative wait.
	t.Setenv("KERI_DRIVER_READY_TIMEOUT", "not-a-number")
	if got := driverReadyTimeout(); got != 30*time.Second {
		t.Errorf("bogus override timeout = %s, want default 30s", got)
	}
}

// In external mode Start adopts a supervised driver over HTTP and never spawns a
// child — so a KeriDriver pointed at a healthy /status comes up without touching
// KERI_DRIVER_PYTHON/SCRIPT at all.
func TestStartExternalModeAdopts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/status" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status":"active","keri_library":"keripy"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	t.Setenv("KERI_DRIVER_EXTERNAL", "1")
	t.Setenv("KERI_DRIVER_PYTHON", "/nonexistent/python-should-never-be-invoked")
	t.Setenv("KERI_DRIVER_SCRIPT", "/nonexistent/server.py")

	d := &KeriDriver{BaseURL: srv.URL, client: &http.Client{Timeout: 2 * time.Second}, managed: true}
	if err := d.Start(); err != nil {
		t.Fatalf("external Start should adopt the healthy driver, got error: %v", err)
	}
	if d.managed {
		t.Error("adopted external driver must be marked unmanaged (managed=false)")
	}
}

// External mode with no reachable driver fails within the timeout rather than
// spawning a child — the supervisor is expected to retry the backend.
func TestStartExternalModeFailsWhenUnreachable(t *testing.T) {
	t.Setenv("KERI_DRIVER_EXTERNAL", "1")
	t.Setenv("KERI_DRIVER_READY_TIMEOUT", "1")
	t.Setenv("KERI_DRIVER_PYTHON", "/nonexistent/python-should-never-be-invoked")

	// Point at a closed port so /status never succeeds.
	d := &KeriDriver{BaseURL: "http://127.0.0.1:1", client: &http.Client{Timeout: 200 * time.Millisecond}, managed: true}
	if err := d.Start(); err == nil {
		t.Fatal("external Start with no driver should return an error, got nil")
	}
	if d.process != nil {
		t.Error("external mode must never spawn a child process")
	}
}
