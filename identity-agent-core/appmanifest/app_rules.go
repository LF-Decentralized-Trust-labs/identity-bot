package appmanifest

import (
	"fmt"
	"identity-agent-core/asset"
	"strings"
	"unicode"
)

// The limits an app's rows are held to. They are written in ADR-012,
// Amendment 5 and in contracts/app-manifest/app-manifest.schema.json, and
// contracts/check_app_manifest_vectors.py holds its own copy.
const (
	largestCPUCores   = 1024
	largestMiB        = 16777216 // 16 TiB
	largestKbps       = 100000000
	longestHost       = 253
	longestLabel      = 63
	largestSecrets    = 64
	longestSecretName = 64
	longestFormat     = 32
	largestQueueSecs  = 86400
	largestBackupGap  = 8760
)

// appRowPresent names the first row of an app that the manifest carries, or
// "" if it carries none. A manifest that is not an app must carry none.
func (m *AppManifest) appRowPresent() string {
	switch {
	case m.ReleaseDigest != "":
		return "release_digest"
	case m.EncryptedMachine != "":
		return "encrypted_machine"
	case m.Store != nil:
		return "store"
	case m.Placement != "":
		return "placement"
	case m.FrontAndBackEnd != nil:
		return "front_and_back_end"
	case m.Secrets != nil:
		return "secrets"
	case m.WhenDown != nil:
		return "when_down"
	case m.Backup != nil:
		return "backup"
	}
	return ""
}

// validateApp checks the rows an app declares. A refusal begins with the name
// of the row it is about, so a maker is told which one to fix. Rows are
// checked in the order the schema lists them; the first fault is reported.
func (m *AppManifest) validateApp() error {
	if strings.TrimFunc(m.Name, unicode.IsSpace) == "" {
		return fmt.Errorf("name: an app must declare a name with at least one character that is not white space")
	}
	if err := m.validateRelease(); err != nil {
		return err
	}
	if err := m.validateResources(); err != nil {
		return err
	}
	switch m.EncryptedMachine {
	case "":
		return fmt.Errorf("encrypted_machine: an app must declare it ('required', 'preferred' or 'not_needed')")
	case EncryptedMachineRequired, EncryptedMachinePreferred, EncryptedMachineNotNeeded:
	default:
		return fmt.Errorf("encrypted_machine: must be 'required', 'preferred' or 'not_needed', got '%s'", m.EncryptedMachine)
	}
	if err := m.validateStore(); err != nil {
		return err
	}
	if err := m.validateVolumes(); err != nil {
		return err
	}
	if m.Placement != "" && m.Placement != "own_machine" && m.Placement != "shared_machine" {
		return fmt.Errorf("placement: must be 'own_machine' or 'shared_machine', got '%s'", m.Placement)
	}
	if err := m.validateEnds(); err != nil {
		return err
	}
	if err := m.validateSecrets(); err != nil {
		return err
	}
	if err := m.validateWhenDown(); err != nil {
		return err
	}
	if err := m.validateBackup(); err != nil {
		return err
	}
	return m.validateOutbound()
}

// validateRelease: the release_digest, and that nothing else in the manifest
// names the release a second way.
func (m *AppManifest) validateRelease() error {
	if m.ReleaseDigest == "" {
		return fmt.Errorf("release_digest: an app must declare it")
	}
	want := "blake3"
	if m.ExecutionType == "container" {
		want = "sha256"
	}
	if !isDigest(m.ReleaseDigest, want) {
		return fmt.Errorf("release_digest: must be '%s:' and 64 lower-case hex digits for a %s app, got '%s'", want, m.ExecutionType, m.ReleaseDigest)
	}
	if len(m.SupportedPlatforms) > 0 {
		return fmt.Errorf("supported_platforms: an app is one release, named by release_digest, so it declares no per-OS binaries")
	}
	// An app is its executable or its image, never both: a block for the
	// other kind would name a second release or be settings nothing reads.
	if m.ExecutionType == "compiled" && m.Container != nil {
		return fmt.Errorf("container: a compiled app is its executable, so it declares no container block")
	}
	if m.ExecutionType == "container" && m.Binary != nil {
		return fmt.Errorf("binary: a container app is its image, so it declares no binary block")
	}
	if m.Binary != nil && (m.Binary.Hash != "" || m.Binary.hashDeclared) {
		return fmt.Errorf("binary.hash: an app's release is named by release_digest alone, so binary.hash is left out")
	}
	if m.Container != nil {
		img := m.Container.Image
		if img == "" || strings.ContainsRune(img, '@') || strings.IndexFunc(img, unicode.IsSpace) >= 0 {
			return fmt.Errorf("container.image: an app's image is a name with no digest and no white space (release_digest is the digest), got '%s'", img)
		}
	}
	return nil
}

func (m *AppManifest) validateResources() error {
	r := m.Resources
	if !(r.CPUCores > 0 && r.CPUCores <= largestCPUCores) {
		return fmt.Errorf("resources.cpu_cores: must be more than 0 and at most %d, got %v", largestCPUCores, r.CPUCores)
	}
	if r.MemoryMB < 1 || r.MemoryMB > largestMiB {
		return fmt.Errorf("resources.memory_mb: must be 1 to %d MiB, got %d", largestMiB, r.MemoryMB)
	}
	if r.DiskMB < 1 || r.DiskMB > largestMiB {
		return fmt.Errorf("resources.disk_mb: must be 1 to %d MiB, got %d", largestMiB, r.DiskMB)
	}
	if r.EgressKbps < 0 || r.EgressKbps > largestKbps {
		return fmt.Errorf("resources.egress_kbps: must be 0 to %d, got %d", largestKbps, r.EgressKbps)
	}
	if r.IngressKbps < 0 || r.IngressKbps > largestKbps {
		return fmt.Errorf("resources.ingress_kbps: must be 0 to %d, got %d", largestKbps, r.IngressKbps)
	}
	return nil
}

func (m *AppManifest) validateStore() error {
	s := m.Store
	if s == nil {
		return fmt.Errorf("store: an app must declare it (format \"none\" and size_mb 0 for an app with no store)")
	}
	if !isToken(s.Format, "-_", longestFormat) {
		return fmt.Errorf("store.format: must be 1 to %d characters, a lower-case letter then lower-case letters, digits, '-' or '_', got '%s'", longestFormat, s.Format)
	}
	if s.Format == "none" {
		if s.SizeMB != 0 {
			return fmt.Errorf("store.size_mb: must be 0 when the format is \"none\", got %d", s.SizeMB)
		}
		return nil
	}
	if s.SizeMB < 1 || s.SizeMB > largestMiB {
		return fmt.Errorf("store.size_mb: must be 1 to %d MiB, got %d", largestMiB, s.SizeMB)
	}
	return nil
}

// validateVolumes: what container.volumes means for an app. A volume is not a
// place on the host ({APP_DATA} does not apply to an app): the one volume an
// app may declare is "store", its own encrypted store (the store row), and the
// value is the absolute path inside the container where the runtime mounts it.
// An app with no store has nothing to mount.
func (m *AppManifest) validateVolumes() error {
	if m.Container == nil {
		return nil
	}
	for key, target := range m.Container.Volumes {
		if key != "store" {
			return fmt.Errorf("container.volumes: an app's only volume is \"store\", its own encrypted store, got '%s'", key)
		}
		if m.Store.Format == "none" {
			return fmt.Errorf("container.volumes: an app with store format \"none\" has no store to mount")
		}
		if !strings.HasPrefix(target, "/") {
			return fmt.Errorf("container.volumes: the store is mounted at an absolute path inside the container, got '%s'", target)
		}
	}
	return nil
}

func (m *AppManifest) validateEnds() error {
	e := m.FrontAndBackEnd
	if e == nil {
		return fmt.Errorf("front_and_back_end: an app must declare it")
	}
	if e.StaticFrontEndURL == nil && e.BackEndPort == nil {
		return fmt.Errorf("front_and_back_end: must declare static_front_end_url, back_end_port or both")
	}
	if e.StaticFrontEndURL != nil && !validStaticURL(*e.StaticFrontEndURL) {
		return fmt.Errorf("front_and_back_end.static_front_end_url: must be https://host[:port][/path] with a lower-case host name, no user, query or fragment, got '%s'", *e.StaticFrontEndURL)
	}
	if e.BackEndPort != nil && (*e.BackEndPort < 1 || *e.BackEndPort > 65535) {
		return fmt.Errorf("front_and_back_end.back_end_port: must be 1 to 65535, got %d", *e.BackEndPort)
	}
	if e.DeviceFrontEnds == nil {
		return fmt.Errorf("front_and_back_end.device_front_ends: must be declared (an empty list says no person uses a front end)")
	}
	seen := map[string]bool{}
	for _, d := range e.DeviceFrontEnds {
		if d != "installed_app" && d != "browser" {
			return fmt.Errorf("front_and_back_end.device_front_ends: each must be 'installed_app' or 'browser', got '%s'", d)
		}
		if seen[d] {
			return fmt.Errorf("front_and_back_end.device_front_ends: '%s' is listed twice", d)
		}
		seen[d] = true
	}
	if e.InstalledApp != nil {
		if err := asset.CheckInstalledAppIdentity("app", e.DeviceFrontEnds, *e.InstalledApp); err != nil {
			return fmt.Errorf("front_and_back_end.%v", err)
		}
	}
	if e.StaticFrontEndURL != nil && !seen["browser"] {
		return fmt.Errorf("front_and_back_end.device_front_ends: a static front end is loaded by a browser, so 'browser' must be listed")
	}
	return nil
}

func (m *AppManifest) validateSecrets() error {
	if m.Secrets == nil {
		return fmt.Errorf("secrets: an app must declare it (an empty list says it needs none)")
	}
	names := *m.Secrets
	if len(names) > largestSecrets {
		return fmt.Errorf("secrets: at most %d names, got %d", largestSecrets, len(names))
	}
	seen := map[string]bool{}
	for _, n := range names {
		if !isToken(n, "_", longestSecretName) {
			return fmt.Errorf("secrets: each name must be 1 to %d characters, a lower-case letter then lower-case letters, digits or '_', got '%s'", longestSecretName, n)
		}
		if seen[n] {
			return fmt.Errorf("secrets: '%s' is listed twice", n)
		}
		seen[n] = true
	}
	return nil
}

func (m *AppManifest) validateWhenDown() error {
	w := m.WhenDown
	if w == nil {
		return fmt.Errorf("when_down: an app must declare it")
	}
	if w.PersonSees != "notice" && w.PersonSees != "last_known_data" {
		return fmt.Errorf("when_down.person_sees: must be 'notice' or 'last_known_data', got '%s'", w.PersonSees)
	}
	if w.QueueRequests == nil {
		return fmt.Errorf("when_down.queue_requests: must be true or false")
	}
	if !*w.QueueRequests {
		if w.QueueMaxSeconds != nil {
			return fmt.Errorf("when_down.queue_max_seconds: left out when queue_requests is false")
		}
		return nil
	}
	if w.QueueMaxSeconds == nil || *w.QueueMaxSeconds < 1 || *w.QueueMaxSeconds > largestQueueSecs {
		return fmt.Errorf("when_down.queue_max_seconds: required, 1 to %d, when queue_requests is true", largestQueueSecs)
	}
	return nil
}

func (m *AppManifest) validateBackup() error {
	b := m.Backup
	if b == nil {
		return fmt.Errorf("backup: an app must declare it (an empty 'what' says nothing is backed up)")
	}
	if b.What == nil {
		return fmt.Errorf("backup.what: must be declared (an empty list says nothing is backed up)")
	}
	seen := map[string]bool{}
	for _, w := range b.What {
		if w != "store" && w != "settings" {
			return fmt.Errorf("backup.what: each must be 'store' or 'settings', got '%s'", w)
		}
		if seen[w] {
			return fmt.Errorf("backup.what: '%s' is listed twice", w)
		}
		seen[w] = true
	}
	if len(b.What) == 0 {
		if b.EveryHours != nil {
			return fmt.Errorf("backup.every_hours: left out when nothing is backed up")
		}
		return nil
	}
	if b.EveryHours == nil || *b.EveryHours < 1 || *b.EveryHours > largestBackupGap {
		return fmt.Errorf("backup.every_hours: required, 1 to %d, when something is backed up", largestBackupGap)
	}
	return nil
}

// validateOutbound: network.allowed_domains, the app's outbound hosts.
func (m *AppManifest) validateOutbound() error {
	hosts := m.Network.AllowedDomains
	if hosts == nil {
		return fmt.Errorf("network.allowed_domains: an app must declare its outbound hosts (an empty list means it reaches none)")
	}
	if len(hosts) > 0 && (m.NetworkMode == "isolated" || m.NetworkMode == "local_only") {
		return fmt.Errorf("network.allowed_domains: network_mode '%s' lets the app reach no outside host, so the list must be empty", m.NetworkMode)
	}
	for i, h := range hosts {
		if !ValidOutboundHost(h) {
			return fmt.Errorf("network.allowed_domains[%d]: must be a host, host:port, *.host or **.host (optionally with :port), all lower case, got '%s'", i, h)
		}
	}
	return nil
}

// ValidOutboundHost reports whether entry is one of the five forms an app may
// list as an outbound host: "host", "host:port", "*.host", "**.host", or either
// wildcard with ":port". host is dot-separated labels of lower-case letters,
// digits and '-' (not at either end), 1 to 63 characters each; the entry
// before any port is at most 253 characters; the host (after any wildcard) is
// not only digits and dots, so an IP address is refused; a wildcard is
// followed by at least two labels, so "*.com" is refused. port is 1 to 65535
// in decimal with no leading zero. Anything else is refused.
func ValidOutboundHost(entry string) bool {
	name, port, hasPort := strings.Cut(entry, ":")
	if hasPort && !validPort(port) {
		return false
	}
	if len(name) == 0 || len(name) > longestHost {
		return false
	}
	labels, minLabels := name, 1
	switch {
	case strings.HasPrefix(name, "**."):
		labels, minLabels = name[3:], 2
	case strings.HasPrefix(name, "*."):
		labels, minLabels = name[2:], 2
	}
	if strings.Trim(labels, "0123456789.") == "" {
		return false
	}
	parts := strings.Split(labels, ".")
	if len(parts) < minLabels {
		return false
	}
	for _, p := range parts {
		if !validLabel(p) {
			return false
		}
	}
	return true
}

func validLabel(l string) bool {
	if len(l) == 0 || len(l) > longestLabel || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func validPort(p string) bool {
	if p == "" || len(p) > 5 || p[0] == '0' {
		return false
	}
	n := 0
	for i := 0; i < len(p); i++ {
		if p[i] < '0' || p[i] > '9' {
			return false
		}
		n = n*10 + int(p[i]-'0')
	}
	return n <= 65535
}

// validStaticURL: "https://" host [":" port] [path]. The host is an exact
// host as ValidOutboundHost reads it, with no wildcard. The path, if any,
// starts with '/' and holds only the characters RFC 3986 allows in a path,
// each % followed by two hex digits. There is no user, query or fragment.
func validStaticURL(u string) bool {
	rest, ok := strings.CutPrefix(u, "https://")
	if !ok {
		return false
	}
	authority, path := rest, ""
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		authority, path = rest[:i], rest[i:]
	}
	if strings.HasPrefix(authority, "*") || !ValidOutboundHost(authority) {
		return false
	}
	for i := 0; i < len(path); i++ {
		c := path[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("-._~!$&'()*+,;=:@/", c) >= 0:
		case c == '%' && i+2 < len(path) && isHex(path[i+1]) && isHex(path[i+2]):
			i += 2
		default:
			return false
		}
	}
	return true
}

func isHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }

// isToken: 1 to max characters, a lower-case letter first, then lower-case
// letters, digits and any of extra.
func isToken(s string, extra string, max int) bool {
	if len(s) == 0 || len(s) > max || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte(extra, c) >= 0) {
			return false
		}
	}
	return true
}

// isDigest: algorithm, ':' and 64 lower-case hex digits.
func isDigest(d, algorithm string) bool {
	hex, ok := strings.CutPrefix(d, algorithm+":")
	if !ok || len(hex) != 64 {
		return false
	}
	for i := 0; i < len(hex); i++ {
		if c := hex[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
