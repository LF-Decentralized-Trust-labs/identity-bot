//go:build linux

package secureenclave

import (
	"encoding/binary"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// A key only this software, on this processor, can derive.
//
// The processor will hand a guest a key derived from secrets it holds and from
// facts about how the guest was launched. Nothing outside the guest can ask for
// it: the request is made from inside, and the host is outside the boundary by
// construction. So a key derived here can encrypt something the operator cannot
// read, without anybody having to store a key anywhere the operator can reach.
//
// The facts it is derived from are chosen by the caller, and that choice is the
// entire security property. Derive from the measurement and the key belongs to
// exactly this software; derive from something the host controls and the host
// can arrange to be handed the same key.

// snpDerivedKeyReq is struct snp_derived_key_req.
type snpDerivedKeyReq struct {
	RootKeySelect    uint32
	_                uint32
	GuestFieldSelect uint64
	VMPL             uint32
	GuestSVN         uint32
	TCBVersion       uint64
}

// snpDerivedKeyResp is struct snp_derived_key_resp: a 64-byte buffer whose
// first 4 bytes are status and whose key follows at offset 4.
type snpDerivedKeyResp struct {
	Data [64]byte
}

// snpGetDerivedKeyIoctl is SNP_GET_DERIVED_KEY —
// _IOWR('S', 0x1, struct snp_guest_request_ioctl).
const snpGetDerivedKeyIoctl = 0xC0205301

// derivedKeyOffset is where the key starts inside snp_derived_key_resp.Data.
const derivedKeyOffset = 4

// Which launch facts a derived key is bound to.
//
// MEASUREMENT and nothing else, deliberately.
//
// The measurement covers the firmware, the kernel, the initramfs and the
// command line — and, now that the root filesystem is verified, the command
// line carries a hash of that too. So a key derived from it belongs to exactly
// this software and no other.
//
// That last part only became true recently, and it is why this field selection
// is safe now and was not before. While the root filesystem sat outside the
// measurement, an operator could replace the agent without moving the
// measurement, and a measurement-derived key would have been handed straight to
// the replacement. The binding looked sound and was not.
//
// Nothing host-controlled is included. POLICY in particular is chosen at launch
// by whoever starts the guest, so including it would let an operator vary a
// field until they were handed a key they wanted.
const guestFieldMeasurement = 1 << 5

// DeriveKey asks the processor for a key bound to this software.
//
// The same software on the same processor gets the same key every time, and
// nothing else gets it at all. That is what lets an instance encrypt its own
// storage with no key stored anywhere: it asks again on the next boot.
//
// purpose separates keys that must not be the same. The firmware returns one
// key per field selection, so two uses deriving "the" key would share it, and a
// weakness in one would be a weakness in the other.
func DeriveKey(purpose string) ([]byte, error) {
	f, err := os.OpenFile(snpGuestDevice, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("no SEV-SNP guest device, so no key can be derived: %w", err)
	}
	defer f.Close()

	req := snpDerivedKeyReq{
		// The VCEK, which is derived from chip secrets and the firmware level.
		RootKeySelect:    0,
		GuestFieldSelect: guestFieldMeasurement,
		// VMPL 0. A key derived at a level is not obtainable from a less
		// privileged one, so this is the level that matters even where nothing
		// runs above it yet.
		VMPL: 0,
	}
	var resp snpDerivedKeyResp

	arg := snpGuestRequestIoctl{
		MsgVersion: 1,
		ReqData:    uint64(uintptr(unsafe.Pointer(&req))),
		RespData:   uint64(uintptr(unsafe.Pointer(&resp))),
	}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(),
		uintptr(snpGetDerivedKeyIoctl), uintptr(unsafe.Pointer(&arg))); errno != 0 {
		return nil, fmt.Errorf("SNP_GET_DERIVED_KEY failed: %v (firmware error 0x%x)", errno, arg.FWErr)
	}
	if arg.FWErr != 0 {
		return nil, fmt.Errorf("the firmware refused to derive a key: 0x%x", arg.FWErr)
	}
	// A non-zero status means no key was written, and the buffer is zeroed — so
	// copying it anyway yields 32 zero bytes that are the right length and would
	// be used as a key by anything that only checks the length.
	if status := binary.LittleEndian.Uint32(resp.Data[0:4]); status != 0 {
		return nil, fmt.Errorf("SNP_GET_DERIVED_KEY returned status 0x%x — no key was produced", status)
	}

	key := make([]byte, DerivedKeySize)
	copy(key, resp.Data[derivedKeyOffset:derivedKeyOffset+DerivedKeySize])
	if allZero(key) {
		return nil, fmt.Errorf("the firmware returned an all-zero key, which is not a key")
	}

	// One key per purpose, from the one the firmware gives.
	//
	// Domain separation rather than a second firmware call, because the firmware
	// returns the same key for the same field selection: two purposes asking for
	// it directly would share a key, and then a weakness in one use is a
	// weakness in the other.
	return deriveForPurpose(key, purpose), nil
}
