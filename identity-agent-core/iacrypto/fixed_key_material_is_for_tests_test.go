package iacrypto

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fixed key material has private halves anyone can rebuild from its seed, so
// an identity founded on it would belong to everyone. Only tests and vector
// generation may reach it. A production path that called it once let a
// request found an identity, or mint a break-glass root, from it.
func TestFixedKeyMaterialIsReachedOnlyFromTests(t *testing.T) {
	root := ".."
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == "vendor" || name == "node_modules" || strings.HasPrefix(name, ".") && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(b), "\n") {
			code := strings.TrimSpace(line)
			if strings.HasPrefix(code, "//") || strings.HasPrefix(code, "func SyntheticHybridKeyMaterial(") {
				continue
			}
			if strings.Contains(code, "SyntheticHybridKeyMaterial(") {
				t.Errorf("%s:%d reaches fixed key material outside a test: %s", path, i+1, code)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
