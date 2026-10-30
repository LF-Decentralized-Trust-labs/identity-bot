package activitylog

// What an anchoring of the record fixes. The record identity seals the digest
// of one of these statements in its key log; an exported conversation carries
// them, so the format is read exactly as it was written.

// CapabilityRecordAnchoring is the governance log's row for an anchoring of
// the record, written just before the anchor that fixes it.
const CapabilityRecordAnchoring = "record.anchoring"

// AnchorStatement is what an anchor fixes: the newest row of the governance
// log and its hash, and the newest entry of every conversation that grew since
// the anchor before.
type AnchorStatement struct {
	Log           AnchoredLog            `json:"log"`
	Conversations []AnchoredConversation `json:"conversations,omitempty"`
	At            string                 `json:"at"`
	// Signer is the identity that signs the governance log, named so the
	// record identity, which the root delegates, vouches for it. Absent from
	// anchors made before it was named.
	Signer string `json:"signer,omitempty"`
}

// AnchoredLog is the log's newest row as an anchor fixes it.
type AnchoredLog struct {
	Row  int64  `json:"row"`
	Head string `json:"head"`
}

// AnchoredConversation is a conversation's newest entry as an anchor fixes it.
type AnchoredConversation struct {
	ID   string `json:"id"`
	Seq  int    `json:"seq"`
	Head string `json:"head"`
}
