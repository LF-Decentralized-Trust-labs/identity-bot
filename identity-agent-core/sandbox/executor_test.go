package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// stubExecutor records what it was handed, so tests can assert the engine passes
// the record and the caller's arguments through unchanged.
type stubExecutor struct {
	gotRecord *CapabilityRecord
	gotArgs   []byte
	result    *InvokeResult
	err       error
}

func (s *stubExecutor) Execute(_ context.Context, rec *CapabilityRecord, args []byte) (*InvokeResult, error) {
	s.gotRecord, s.gotArgs = rec, args
	if s.err != nil {
		return nil, s.err
	}
	if s.result != nil {
		return s.result, nil
	}
	return &InvokeResult{CapabilityID: rec.ID, Status: 200, Body: []byte(`{"ok":true}`)}, nil
}

func withCleanExecutors(t *testing.T) {
	t.Helper()
	unregisterExecutorsForTest()
	t.Cleanup(unregisterExecutorsForTest)
}

func TestRegisterExecutorMakesTypeInvocable(t *testing.T) {
	withCleanExecutors(t)
	stub := &stubExecutor{}
	if err := RegisterExecutor("demo_runner", stub); err != nil {
		t.Fatalf("register: %v", err)
	}
	if executorFor("demo_runner") == nil {
		t.Fatal("registered executor is not resolvable")
	}
	if executorFor("never_registered") != nil {
		t.Error("an unregistered type resolved to something")
	}
}

func TestRegisterExecutorRejectsBadInput(t *testing.T) {
	withCleanExecutors(t)
	cases := []struct {
		name string
		key  string
		exec Executor
	}{
		{"nil implementation", "demo_runner", nil},
		{"empty name", "", &stubExecutor{}},
		{"uppercase", "DemoRunner", &stubExecutor{}},
		{"punctuation", "demo-runner", &stubExecutor{}},
		{"leading underscore", "_demo", &stubExecutor{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := RegisterExecutor(c.key, c.exec); err == nil {
				t.Error("expected registration to be rejected")
			}
		})
	}
}

// A built-in type must not be silently replaced: the engine implements or reserves
// those, and shadowing one would change behaviour depending on import order.
func TestRegisterExecutorCannotShadowBuiltin(t *testing.T) {
	withCleanExecutors(t)
	for _, name := range []string{"external_api", "internal_api", "host_control", "ai_agent", "plugin"} {
		if err := RegisterExecutor(name, &stubExecutor{}); err == nil {
			t.Errorf("registering built-in %q should have failed", name)
		}
	}
}

// Two components each believing they own an executor type is a bug worth surfacing,
// not resolving by last-write-wins.
func TestRegisterExecutorRejectsDuplicate(t *testing.T) {
	withCleanExecutors(t)
	if err := RegisterExecutor("demo_runner", &stubExecutor{}); err != nil {
		t.Fatalf("first registration: %v", err)
	}
	err := RegisterExecutor("demo_runner", &stubExecutor{})
	if err == nil {
		t.Fatal("second registration should have failed")
	}
	if !strings.Contains(err.Error(), "already registered") {
		t.Errorf("error should say why: %v", err)
	}
}

// Pack validation is what gates a capability into the registry at all, so a
// registered type must become acceptable there — otherwise an executor could be
// installed that no capability is ever allowed to declare.
func TestPackAcceptsRegisteredExecutorTypeAndRejectsUnknown(t *testing.T) {
	withCleanExecutors(t)

	pack := func(execType string) []byte {
		return []byte(`{"pack":"t","capabilities":[{"id":"demo.thing.run","name":"Run",
			"domain":"demo","executor_type":"` + execType + `","impact":"read","enabled":true}]}`)
	}

	if _, err := ParseCapabilityPack(pack("demo_runner")); err == nil {
		t.Fatal("an unregistered type should be rejected before registration")
	}
	if err := RegisterExecutor("demo_runner", &stubExecutor{}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := ParseCapabilityPack(pack("demo_runner")); err != nil {
		t.Fatalf("a registered type should be accepted: %v", err)
	}
	if _, err := ParseCapabilityPack(pack("still_unknown")); err == nil {
		t.Error("an unregistered type should still be rejected")
	}
}

func TestRegisteredExecutorTypesIsSorted(t *testing.T) {
	withCleanExecutors(t)
	for _, n := range []string{"zeta_runner", "alpha_runner", "mid_runner"} {
		if err := RegisterExecutor(n, &stubExecutor{}); err != nil {
			t.Fatalf("register %s: %v", n, err)
		}
	}
	got := RegisteredExecutorTypes()
	want := []string{"alpha_runner", "mid_runner", "zeta_runner"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// The engine must hand the executor the record and the caller's arguments verbatim:
// the record is the trusted input, the arguments the untrusted one, and an executor
// cannot maintain that distinction if the engine reshapes either.
func TestExecutorReceivesRecordAndArgsUnchanged(t *testing.T) {
	withCleanExecutors(t)
	stub := &stubExecutor{}
	if err := RegisterExecutor("demo_runner", stub); err != nil {
		t.Fatalf("register: %v", err)
	}
	rec := &CapabilityRecord{
		ID: "demo.thing.run", ExecutorType: "demo_runner", Impact: "read", Enabled: true,
		ExecutorConfig: json.RawMessage(`{"setting":"from-the-record"}`),
	}
	args := []byte(`{"from":"the-caller"}`)

	res, err := executorFor("demo_runner").Execute(context.Background(), rec, args)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if res.Status != 200 {
		t.Errorf("status = %d, want 200", res.Status)
	}
	if string(stub.gotArgs) != string(args) {
		t.Errorf("args = %s, want %s", stub.gotArgs, args)
	}
	if string(stub.gotRecord.ExecutorConfig) != `{"setting":"from-the-record"}` {
		t.Errorf("executor config did not arrive intact: %s", stub.gotRecord.ExecutorConfig)
	}
}

func TestExecutorErrorPropagates(t *testing.T) {
	withCleanExecutors(t)
	sentinel := errors.New("machinery unreachable")
	if err := RegisterExecutor("demo_runner", &stubExecutor{err: sentinel}); err != nil {
		t.Fatalf("register: %v", err)
	}
	_, err := executorFor("demo_runner").Execute(context.Background(),
		&CapabilityRecord{ID: "demo.thing.run", ExecutorType: "demo_runner"}, nil)
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want %v", err, sentinel)
	}
}

func TestExecutorConfigSurvivesPersistence(t *testing.T) {
	store, err := NewSandboxStore(t.TempDir())
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	rec := CapabilityRecord{
		ID: "demo.thing.persist", Name: "Persist", Domain: "demo",
		ExecutorType: "external_api", Impact: "read", Enabled: true,
		ExecutorConfig: json.RawMessage(`{"nested":{"a":1},"list":[1,2,3]}`),
	}
	if err := store.UpsertCapabilityRecord(rec); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, err := store.GetCapabilityRecord("demo.thing.persist")
	if err != nil || got == nil {
		t.Fatalf("get: %v (record %v)", err, got)
	}
	var round map[string]any
	if err := json.Unmarshal(got.ExecutorConfig, &round); err != nil {
		t.Fatalf("executor config did not round-trip as JSON: %v", err)
	}
	if _, ok := round["nested"]; !ok {
		t.Errorf("nested structure lost: %s", got.ExecutorConfig)
	}
}
