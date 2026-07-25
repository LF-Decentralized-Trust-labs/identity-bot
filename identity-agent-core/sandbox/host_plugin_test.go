package sandbox

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeebo/blake3"
)

func hostManifest(binPath, hash string) *AppManifest {
	return &AppManifest{
		ID: "test-host-plugin", Name: "Test Host Plugin",
		ExecutionType: "compiled", DisplayMethod: "terminal", NetworkMode: "local_only",
		Isolation: "host",
		Binary:    &BinaryConfig{Path: binPath, Hash: hash},
		Network:   NetworkPermissions{TLSMode: "mitm"},
		LogLevel:  "metadata",
		Resources: ResourceLimits{MemoryMB: 64},
	}
}

// Validation: host isolation demands a compiled binary with a pinned hash;
// unknown isolation values are rejected; legacy manifests default to sandbox.
func TestHostIsolationValidation(t *testing.T) {
	m := hostManifest("/bin/x", "blake3:aa")
	if err := m.Validate(); err != nil {
		t.Fatalf("valid host manifest rejected: %v", err)
	}
	if m.EffectiveIsolation() != "host" {
		t.Fatal("effective isolation must be host")
	}

	bad := hostManifest("/bin/x", "blake3:aa")
	bad.Isolation = "chroot"
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "isolation") {
		t.Fatalf("unknown isolation must be rejected, got %v", err)
	}

	noHash := hostManifest("/bin/x", "")
	if err := noHash.Validate(); err == nil || !strings.Contains(err.Error(), "hash") {
		t.Fatalf("host plug-in without hash must be rejected, got %v", err)
	}

	container := hostManifest("/bin/x", "blake3:aa")
	container.ExecutionType = "container"
	container.Binary = nil
	container.Container = &ContainerConfig{Image: "img"}
	if err := container.Validate(); err == nil || !strings.Contains(err.Error(), "compiled") {
		t.Fatalf("host plug-in must be compiled, got %v", err)
	}

	legacy := hostManifest("/bin/x", "")
	legacy.Isolation = ""
	if legacy.EffectiveIsolation() != "sandbox" {
		t.Fatal("legacy manifests must default to sandbox isolation")
	}
	if err := legacy.Validate(); err != nil {
		t.Fatalf("legacy sandbox manifest must not need a hash: %v", err)
	}
}

// Launch-time verification: matching hash passes; mismatch and missing pin refuse.
func TestVerifyHostBinary(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "driver")
	content := []byte("#!/bin/sh\necho driver\n")
	if err := os.WriteFile(bin, content, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := blake3.Sum256(content)
	good := "blake3:" + hex.EncodeToString(sum[:])

	if err := verifyHostBinary(hostManifest(bin, good)); err != nil {
		t.Fatalf("matching hash must pass: %v", err)
	}
	if err := verifyHostBinary(hostManifest(bin, "blake3:"+strings.Repeat("00", 32))); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("hash mismatch must refuse launch, got %v", err)
	}
	if err := verifyHostBinary(hostManifest(bin, "")); err == nil || !strings.Contains(err.Error(), "no pinned hash") {
		t.Fatalf("missing pin must refuse launch, got %v", err)
	}
	if err := verifyHostBinary(hostManifest(bin, "sha256:abcd")); err == nil || !strings.Contains(err.Error(), "format") {
		t.Fatalf("non-blake3 pin must refuse launch, got %v", err)
	}
	// Sandboxed manifests are untouched by this check.
	sandboxed := hostManifest(bin, "")
	sandboxed.Isolation = "sandbox"
	if err := verifyHostBinary(sandboxed); err != nil {
		t.Fatalf("sandbox manifests must skip verification: %v", err)
	}
}

// slowInvoker records concurrent entries into the executor.
type slowInvoker struct {
	mu       sync.Mutex
	inFlight int
	max      int
}

func (s *slowInvoker) Invoke(ctx context.Context, appID, capabilityID string, body []byte) (*InvokeResult, error) {
	s.mu.Lock()
	s.inFlight++
	if s.inFlight > s.max {
		s.max = s.inFlight
	}
	s.mu.Unlock()
	time.Sleep(60 * time.Millisecond)
	s.mu.Lock()
	s.inFlight--
	s.mu.Unlock()
	return &InvokeResult{CapabilityID: capabilityID, Status: 200, Body: []byte(`{}`)}, nil
}

// One screen = one driver: concurrent invocations of a host_control capability
// serialize; a non-host capability runs concurrently.
func TestHostControlSessionLockSerializes(t *testing.T) {
	inv := &slowInvoker{}
	m := registryTestManager(t)
	m.invoker = inv
	m.manifests["hostplug"] = &AppManifest{
		ID: "hostplug",
		Provides: []ProvidedCapability{
			{ID: "host.computer_use.run", Name: "Computer use", HostControl: true},
			{ID: "dev.tool.run", Name: "Plain tool"},
		},
	}
	caller := CallerContext{Remote: false, CallerAID: "local-owner"}

	run := func(capID string, n int) int {
		inv.mu.Lock()
		inv.max = 0
		inv.mu.Unlock()
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := m.InvokeCapability(context.Background(), caller, capID, []byte(`{}`)); err != nil {
					t.Errorf("invoke: %v", err)
				}
			}()
		}
		wg.Wait()
		inv.mu.Lock()
		defer inv.mu.Unlock()
		return inv.max
	}

	if max := run("host.computer_use.run", 4); max != 1 {
		t.Fatalf("host_control must serialize (max in-flight %d)", max)
	}
	if max := run("dev.tool.run", 4); max < 2 {
		t.Fatalf("non-host capability should run concurrently (max in-flight %d)", max)
	}
}
