package recovery

import (
	"os"
	"path/filepath"
	"testing"

	"identity-agent-core/backup"
)

// Whatever the backup deliberately leaves out, a restore does not write,
// whatever an archive carries: which machines may act, which tokens are good,
// and the identity database outside its own checked section.
func TestARestoreDoesNotWriteWhatTheBackupLeavesOut(t *testing.T) {
	dir := t.TempDir()
	svc := NewService(dir, nil, nil)
	extra := map[string][]byte{backup.FileSectionPrefix + "kept.json": []byte(`{"kept":true}`)}
	refused := []string{"controller_grants.json", "agent_bodies.json", "mcp_tokens.json", "identity.db",
		"secureenclave/machine_key.sep", "recovery_sessions/x.json"}
	for _, name := range refused {
		extra[backup.FileSectionPrefix+name] = []byte("planted")
	}
	payload, err := RestoreFromArchive(buildTestArchiveWith(t, testMnemonic, nil, extra), OpenRequest{Mnemonic: testMnemonic})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.applyPayload(payload); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "kept.json")); string(b) != `{"kept":true}` {
		t.Fatalf("an ordinary file did not come back: %q", b)
	}
	for _, name := range refused {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(name))); !os.IsNotExist(err) {
			t.Errorf("%s was written from the archive", name)
		}
	}
}
