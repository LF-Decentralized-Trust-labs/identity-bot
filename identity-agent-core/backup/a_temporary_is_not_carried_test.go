package backup

import (
	"os"
	"path/filepath"
	"testing"
)

// A temporary left beside a record, at any depth, is never carried: it is a
// copy of something carried in its own right, and a holding's is its private
// key. The record itself still is.
func TestATemporaryIsNotCarried(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "shares_held"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"shares_held/E.json":           `{"key":"kept"}`,
		"shares_held/E.json.tmp-12345": `{"key":"a copy"}`,
		"didcomm_keys.json.tmp-678":    `{"key":"a copy"}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(name)), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c := &Collector{DataDir: dir}
	bundle := &PayloadBundle{Sections: map[string][]byte{}}
	skipped, err := c.collectEveryOtherFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := bundle.Sections[FileSectionPrefix+"shares_held/E.json"]; !ok {
		t.Fatal("the record itself was not carried")
	}
	for _, name := range []string{"shares_held/E.json.tmp-12345", "didcomm_keys.json.tmp-678"} {
		if _, ok := bundle.Sections[FileSectionPrefix+name]; ok {
			t.Fatalf("%s was carried", name)
		}
		found := false
		for _, s := range skipped {
			found = found || s.Path == name
		}
		if !found {
			t.Fatalf("%s was left out without saying so", name)
		}
	}
}
