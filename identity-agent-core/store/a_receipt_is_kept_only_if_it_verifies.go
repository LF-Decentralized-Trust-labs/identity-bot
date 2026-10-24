package store

import (
	"fmt"

	"identity-agent-core/drivers"
)

// A witness receipt is kept only if it verifies, and read back only if it
// still does.
//
// Receipts are kept one per event and witness. Keeping whatever arrived first
// let anybody who could reach a route that stores receipts plant a junk one
// under a designated witness's name before the real one came back, and the
// real one was then dropped as a duplicate: that witness never counted for
// that event. So the check is here, where every path that stores a receipt
// passes, rather than in each path.
//
// A witness is named by a non-transferable identifier, which is its key, so a
// receipt verifies with nothing fetched: either that witness signed the event's
// identifier or it did not. Only verified receipts are stored, so a stored one
// is replaced only by another the same witness signed. Receipts kept before
// this check are filtered on the way out, and a verified receipt replaces one.

// ErrReceiptDoesNotVerify is returned for a receipt that was not signed by
// the witness it names, over the event it names.
var ErrReceiptDoesNotVerify = fmt.Errorf("the receipt does not verify")

func checkReceipt(r WitnessReceiptRecord) error {
	if err := drivers.VerifyReceipt(r.WitnessAID, r.EventSAID, r.CesrSignature); err != nil {
		return fmt.Errorf("%w: %v", ErrReceiptDoesNotVerify, err)
	}
	return nil
}

func verifiedReceipts(in []WitnessReceiptRecord) []WitnessReceiptRecord {
	out := make([]WitnessReceiptRecord, 0, len(in))
	for _, r := range in {
		if checkReceipt(r) == nil {
			out = append(out, r)
		}
	}
	return out
}
