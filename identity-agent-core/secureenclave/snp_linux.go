//go:build linux

package secureenclave

import (
	"encoding/binary"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The guest side of SEV-SNP attestation, against the kernel's sev-guest ABI
// (uapi/linux/sev-guest.h). The structures below mirror that header exactly;
// getting a field width wrong here produces a garbage report rather than an
// error, so they are laid out to match rather than to look tidy.

const snpGuestDevice = "/dev/sev-guest"

// snpReportReq is struct snp_report_req.
type snpReportReq struct {
	UserData [ReportDataSize]byte
	VMPL     uint32
	_        [28]byte
}

// snpReportResp is struct snp_report_resp: a 4000-byte buffer whose first
// 32 bytes are a header and whose report begins at offset 32.
type snpReportResp struct {
	Data [4000]byte
}

// snpGuestRequestIoctl is struct snp_guest_request_ioctl.
type snpGuestRequestIoctl struct {
	MsgVersion uint8
	_          [7]byte // alignment before the 64-bit pointers
	ReqData    uint64
	RespData   uint64
	FWErr      uint64
}

// snpGetReportIoctl is SNP_GET_REPORT — _IOWR('S', 0x0, struct snp_guest_request_ioctl).
const snpGetReportIoctl = 0xC0205300

// reportOffset is where the report itself starts inside snp_report_resp.Data.
const reportOffset = 32

func snpAvailable() bool {
	_, err := os.Stat(snpGuestDevice)
	return err == nil
}

func getSNPReport(reportData []byte) ([]byte, error) {
	if len(reportData) != ReportDataSize {
		return nil, fmt.Errorf("report data must be %d bytes", ReportDataSize)
	}
	f, err := os.OpenFile(snpGuestDevice, os.O_RDWR, 0)
	if err != nil {
		// Not an SNP guest, or the guest driver is missing. Either way this
		// process cannot prove anything about itself, and saying so is the
		// honest answer.
		return nil, fmt.Errorf("no SEV-SNP guest device: %w", err)
	}
	defer f.Close()

	var req snpReportReq
	copy(req.UserData[:], reportData)
	var resp snpReportResp

	arg := snpGuestRequestIoctl{
		MsgVersion: 1,
		ReqData:    uint64(uintptr(unsafe.Pointer(&req))),
		RespData:   uint64(uintptr(unsafe.Pointer(&resp))),
	}

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(),
		uintptr(snpGetReportIoctl), uintptr(unsafe.Pointer(&arg))); errno != 0 {
		return nil, fmt.Errorf("SNP_GET_REPORT failed: %v (firmware error 0x%x)", errno, arg.FWErr)
	}
	if arg.FWErr != 0 {
		return nil, fmt.Errorf("SNP firmware refused the report request: 0x%x", arg.FWErr)
	}

	// The response header's first four bytes are STATUS. A non-zero status means
	// no report was written — and the buffer we allocated is zeroed, so copying
	// it anyway yields 1184 zero bytes that are the right length and carry every
	// field a caller expects to read. Nothing downstream distinguishes that from
	// a real report by shape; it has to be caught here.
	if status := binary.LittleEndian.Uint32(resp.Data[0:4]); status != 0 {
		return nil, fmt.Errorf("SNP_GET_REPORT returned status 0x%x — no report was produced", status)
	}
	// REPORT_SIZE follows it. A short report is a truncated one, and reading past
	// what the firmware wrote returns whatever the buffer held.
	if size := binary.LittleEndian.Uint32(resp.Data[4:8]); size < ReportSize {
		return nil, fmt.Errorf("SNP_GET_REPORT wrote %d bytes, want at least %d", size, ReportSize)
	}

	report := make([]byte, ReportSize)
	copy(report, resp.Data[reportOffset:reportOffset+ReportSize])
	return report, nil
}
