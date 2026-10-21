//go:build windows

package agenthost

import (
	"os"

	"golang.org/x/sys/windows"
)

// diskSpace is the free and total space, in gigabytes, of the system drive.
func diskSpace() (free, total float64) {
	drive := os.Getenv("SystemDrive")
	if drive == "" {
		drive = "C:"
	}
	p, err := windows.UTF16PtrFromString(drive + `\`)
	if err != nil {
		return 0, 0
	}
	var avail, tot, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &avail, &tot, &totalFree); err != nil {
		return 0, 0
	}
	return round1(float64(avail) / (1 << 30)), round1(float64(tot) / (1 << 30))
}
