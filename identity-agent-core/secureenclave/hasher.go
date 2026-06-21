package secureenclave

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/zeebo/blake3"
)

// ComponentHasher returns the Blake3-256 hex digest for a named component.
type ComponentHasher func() (hash string, err error)

// Registry collects component hashers for the full application chain.
type Registry struct {
	hashers map[string]ComponentHasher
}

func NewRegistry() *Registry {
	return &Registry{hashers: make(map[string]ComponentHasher)}
}

func (r *Registry) Register(name string, hasher ComponentHasher) {
	r.hashers[name] = hasher
}

func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.hashers))
	for name := range r.hashers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ComponentDigests returns sorted component Blake3-256 digests.
func (r *Registry) ComponentDigests() (map[string]string, error) {
	out := make(map[string]string, len(r.hashers))
	for name, hasher := range r.hashers {
		hash, err := hasher()
		if err != nil {
			return nil, fmt.Errorf("component %q: %w", name, err)
		}
		out[name] = hash
	}
	return out, nil
}

// ChainHash computes Blake3-256 over the sorted component name=digest pairs.
func (r *Registry) ChainHash() (string, map[string]string, error) {
	digests, err := r.ComponentDigests()
	if err != nil {
		return "", nil, err
	}
	names := make([]string, 0, len(digests))
	for name := range digests {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	for i, name := range names {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(name)
		b.WriteByte('=')
		b.WriteString(digests[name])
	}
	sum := blake3.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:]), digests, nil
}

// DefaultRegistry wires the standard identity-agent component chain.
func DefaultRegistry(dataDir string) *Registry {
	reg := NewRegistry()
	reg.Register("go_backend", fileHasher(resolveBinaryPath()))
	reg.Register("python_keri_driver", fileHasher(resolveKeriDriverScript()))
	if path := resolveAuthProviderBinary(); path != "" {
		reg.Register("auth_provider", fileHasher(path))
	}
	reg.Register("sandbox_apps", sandboxAppsHasher(dataDir))
	return reg
}

func resolveBinaryPath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return exe
}

func resolveKeriDriverScript() string {
	if path := os.Getenv("KERI_DRIVER_SCRIPT"); path != "" {
		return path
	}
	exe, err := os.Executable()
	if err == nil {
		candidate := filepath.Join(filepath.Dir(exe), "drivers", "keri-core", "server.py")
		if _, statErr := os.Stat(candidate); statErr == nil {
			return candidate
		}
	}
	for _, rel := range []string{
		"./drivers/keri-core/server.py",
		"../drivers/keri-core/server.py",
	} {
		if _, statErr := os.Stat(rel); statErr == nil {
			return rel
		}
	}
	return ""
}

func resolveAuthProviderBinary() string {
	candidates := []string{
		"../authproviders/identity-levels/identity-levels",
		"./authproviders/identity-levels/identity-levels",
	}
	exe, err := os.Executable()
	if err == nil {
		candidates = append([]string{
			filepath.Join(filepath.Dir(exe), "authproviders", "identity-levels", "identity-levels"),
		}, candidates...)
	}
	for _, path := range candidates {
		if st, err := os.Stat(path); err == nil && !st.IsDir() {
			return path
		}
	}
	return ""
}

func fileHasher(path string) ComponentHasher {
	return func() (string, error) {
		if path == "" {
			return "", fmt.Errorf("path not configured")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		sum := blake3.Sum256(data)
		return hex.EncodeToString(sum[:]), nil
	}
}

func sandboxAppsHasher(dataDir string) ComponentHasher {
	manifestsDir := filepath.Join(".", "manifests")
	if dataDir != "" {
		manifestsDir = filepath.Join(dataDir, "..", "manifests")
	}
	return func() (string, error) {
		entries, err := os.ReadDir(manifestsDir)
		if err != nil {
			// Non-fatal when sandbox manifests are absent.
			sum := blake3.Sum256([]byte("sandbox_apps:empty"))
			return hex.EncodeToString(sum[:]), nil
		}
		var parts []string
		for _, ent := range entries {
			if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
				continue
			}
			path := filepath.Join(manifestsDir, ent.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				return "", err
			}
			digest := blake3.Sum256(data)
			parts = append(parts, ent.Name()+"="+hex.EncodeToString(digest[:]))
		}
		sort.Strings(parts)
		sum := blake3.Sum256([]byte(strings.Join(parts, "\n")))
		return hex.EncodeToString(sum[:]), nil
	}
}