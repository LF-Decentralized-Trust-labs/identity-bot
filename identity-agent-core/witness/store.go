package witness

// Store persists witness pool state, KEL replicas, and finalization.
type Store interface {
	GetConfig(key string) (string, error)
	SetConfig(key, value string) error

	GetContactMeta(aid string) (*ContactMeta, error)
	SaveContactMeta(m ContactMeta) error
	ListContactMeta() ([]ContactMeta, error)

	StoreKelEvent(ev KelEvent) error
	GetKelEvents(signerAID string) ([]KelEvent, error)
	LastKelSeq(signerAID string) (int, error)
	CountKelEvents(signerAID string) (int, error)
	// SetKelSignatures replaces the signatures held for the event at seq.
	SetKelSignatures(signerAID string, seq int, signatures []string) error
	// SupersedeKelEvents moves every event at or after by's place to the
	// superseded record and stores by in their stead, in one transaction.
	SupersedeKelEvents(signerAID string, by KelEvent) error
	GetSupersededKelEvents(signerAID string) ([]KelEvent, error)
	// SaveKelConflict keeps a conflicting event, once.
	SaveKelConflict(c KelConflict) error
	GetKelConflicts(signerAID string) ([]KelConflict, error)

	SaveIssuedReceipt(r IssuedReceipt) error
	// GetIssuedReceipt is the receipt this agent issued for an event, or nil.
	GetIssuedReceipt(signerAID, eventSAID string) (*IssuedReceipt, error)
	GetFinalization(eventSAID string) (*FinalizationState, error)
	SaveFinalization(f FinalizationState) error

	CountWitnessingFor() (int, error)
	RecordSelfHealAttempt(contactAID string, at string) error
	LastSelfHealAttempt(contactAID string) (string, error)
	CountSelfHealAttemptsSince(since string) (int, error)
}
