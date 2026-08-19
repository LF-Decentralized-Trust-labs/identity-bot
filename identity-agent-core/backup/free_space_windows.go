//go:build windows

package backup

import (
	"golang.org/x/sys/windows"
)

// freeBytes is how much room is left where archives are kept.
//
// GetDiskFreeSpaceExW reports the free space available to the calling user,
// which is the number that matters: a quota can leave a volume with room on it
// and none for us.
func freeBytes(dir string) (int64, error) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, err
	}
	var availableToCaller, total, free uint64
	if err := windows.GetDiskFreeSpaceEx(p, &availableToCaller, &total, &free); err != nil {
		return 0, err
	}
	return int64(availableToCaller), nil
}
