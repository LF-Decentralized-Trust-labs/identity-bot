//go:build !linux

package secureenclave

import "fmt"

// Everywhere that is not Linux: there is no SEV-SNP guest, and saying so
// plainly is better than returning something empty that a caller might read as
// a report.

func snpAvailable() bool { return false }

func getSNPReport([]byte) ([]byte, error) {
	return nil, fmt.Errorf("SEV-SNP attestation is only available inside a Linux SNP guest")
}
