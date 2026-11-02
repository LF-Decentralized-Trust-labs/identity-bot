package secureenclave

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// IS THE DATA DIRECTORY ON THE ENCRYPTED VOLUME?
//
// On the black box the data directory is a LUKS volume mounted at
// /var/lib/identity-agent. If it is not mounted, the directory is an ordinary
// folder on the root filesystem and everything written there is unprotected.
// The way to tell is to find which mount the directory is on, and ask whether
// the block device behind that mount is a dm-crypt mapping.

// defaultSealedDataDir is where the sealed image mounts the volume.
const defaultSealedDataDir = "/var/lib/identity-agent"

// The files read, as vars so a test can supply its own.
var (
	mountInfoPath = "/proc/self/mountinfo"
	sysfsRoot     = "/sys"
)

// agentDataDir is the directory the agent keeps its state in.
func agentDataDir() string {
	if d := os.Getenv("AGENT_DATA_DIR"); d != "" {
		return d
	}
	return defaultSealedDataDir
}

// dataDirIsOnADmCryptVolume returns nil when dir sits on a dm-crypt device, and
// otherwise says what it is on instead.
func dataDirIsOnADmCryptVolume(dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	f, err := os.Open(mountInfoPath)
	if err != nil {
		return fmt.Errorf("cannot read the mount table: %w", err)
	}
	defer f.Close()

	var bestMount, bestDev string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		// id parent major:minor root mountpoint opts [optional...] - fstype source superopts
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 {
			continue
		}
		mp := unescapeMountField(fields[4])
		if !pathIsUnder(abs, mp) {
			continue
		}
		// The most specific mount wins; among equals the later one is on top.
		if len(mp) >= len(bestMount) {
			bestMount, bestDev = mp, fields[2]
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("cannot read the mount table: %w", err)
	}
	if bestMount == "" {
		return fmt.Errorf("%s is not on any mount", abs)
	}
	if _, err := parseMajorMinor(bestDev); err != nil {
		return fmt.Errorf("%s is on %s, whose device %q is not a block device", abs, bestMount, bestDev)
	}
	uuid, err := os.ReadFile(filepath.Join(sysfsRoot, "dev", "block", bestDev, "dm", "uuid"))
	if err != nil {
		return fmt.Errorf("%s is on %s (device %s), which is not a device-mapper volume", abs, bestMount, bestDev)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(uuid)), "CRYPT-") {
		return fmt.Errorf("%s is on %s (device %s), which is not an encrypted volume", abs, bestMount, bestDev)
	}
	return nil
}

func pathIsUnder(path, mount string) bool {
	if mount == "/" {
		return true
	}
	return path == mount || strings.HasPrefix(path, mount+"/")
}

func parseMajorMinor(s string) ([2]int, error) {
	maj, min, ok := strings.Cut(s, ":")
	if !ok {
		return [2]int{}, fmt.Errorf("not major:minor")
	}
	a, err1 := strconv.Atoi(maj)
	b, err2 := strconv.Atoi(min)
	if err1 != nil || err2 != nil {
		return [2]int{}, fmt.Errorf("not major:minor")
	}
	return [2]int{a, b}, nil
}

// unescapeMountField undoes the kernel's octal escapes (a space is \040).
func unescapeMountField(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
