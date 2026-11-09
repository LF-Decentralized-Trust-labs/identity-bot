package backup

import (
	"bytes"
	"os"
	"testing"

	"identity-agent-core/secureenclave/seedwraptest"
)

// A sign-in token to somebody's cloud drive is only as private as the key that
// seals it, so that key goes through the same wrapper the root seed does.

func TestTheCredentialKeyIsNotAPlainFileWhereTheMachineCanWrapIt(t *testing.T) {
	seedwraptest.ThisMachineCanProtectASeed(t)
	dir := t.TempDir()
	cs, err := NewCredentialStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.Save("c1", RemoteCredentialSecrets{OAuthRefreshToken: "1//refresh", OAuthClientID: "id"}); err != nil {
		t.Fatal(err)
	}
	onDisk, _ := os.ReadFile(cs.masterKeyPath())
	if bytes.Contains(onDisk, cs.masterKey) || len(onDisk) == 32 {
		t.Fatal("the key that seals the credentials is on disk in the clear on a machine that can wrap it")
	}
	if !bytes.Contains(onDisk, []byte("test-wrap")) {
		t.Fatalf("the file does not say what protects it: %s", onDisk)
	}
	// A new process on the same machine opens what the first sealed.
	again, err := NewCredentialStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := again.Load("c1")
	if err != nil || got.OAuthRefreshToken != "1//refresh" {
		t.Fatalf("reopened: %+v %v", got, err)
	}
}

func TestAKeyWrittenBeforeWrappingIsStillOpenedAndThenWrapped(t *testing.T) {
	// Written by the previous build: a bare 32-byte file, and a credential it sealed.
	dir := t.TempDir()
	if err := os.MkdirAll(dir+"/backup", 0700); err != nil {
		t.Fatal(err)
	}
	old := bytes.Repeat([]byte{7}, 32)
	if err := os.WriteFile(dir+"/backup/credentials_master.key", old, 0600); err != nil {
		t.Fatal(err)
	}
	prev := &CredentialStore{dir: dir + "/backup", masterKey: old}
	if err := prev.Save("c1", RemoteCredentialSecrets{AccessKey: "ak", SecretKey: "sk"}); err != nil {
		t.Fatal(err)
	}

	seedwraptest.ThisMachineCanProtectASeed(t)
	cs, err := NewCredentialStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := cs.Load("c1")
	if err != nil || got.AccessKey != "ak" {
		t.Fatalf("a credential sealed before wrapping was lost: %+v %v", got, err)
	}
	if onDisk, _ := os.ReadFile(cs.masterKeyPath()); len(onDisk) == 32 {
		t.Fatal("the old key was left as a plain file though a wrapper works here")
	}
	// and survives one more start
	again, err := NewCredentialStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := again.Load("c1"); err != nil || got.SecretKey != "sk" {
		t.Fatalf("after the upgrade: %+v %v", got, err)
	}
}

func TestAnUnreadableCredentialKeyIsNotReplacedWithANewOne(t *testing.T) {
	seedwraptest.ThisMachineCanProtectASeed(t)
	dir := t.TempDir()
	cs, _ := NewCredentialStore(dir)
	_ = cs.Save("c1", RemoteCredentialSecrets{AccessKey: "ak"})
	// The same file, on a machine whose wrapper cannot open it.
	seedwraptest.ThisMachineIsAPhoneWithNoWrapper(t)
	if _, err := NewCredentialStore(dir); err == nil {
		t.Fatal("a key this machine cannot open must be an error, not a fresh key that orphans every credential")
	}
}
