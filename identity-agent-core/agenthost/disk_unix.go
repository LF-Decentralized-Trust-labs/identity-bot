//go:build !windows

package agenthost

import "syscall"

// diskSpace is the free and total space, in gigabytes, of the volume holding
// the root directory.
func diskSpace() (free, total float64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs("/", &st); err != nil {
		return 0, 0
	}
	bs := float64(st.Bsize)
	return round1(float64(st.Bavail) * bs / (1 << 30)), round1(float64(st.Blocks) * bs / (1 << 30))
}
