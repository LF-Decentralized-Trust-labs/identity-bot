package witness

// Store persists witness pool state, KEL replicas, and finalization.
type Store interface {
	GetConfig(key string) (string, error)
	SetConfig(key, value string) error

	GetContactMeta(aid string) (*ContactMeta, error)
	SaveContactMeta(m ContactMeta) error
	ListContactMeta() ([]ContactMeta, error)
	// DeleteContactMeta removes the record, as if none had been made.
	DeleteContactMeta(aid string) error

	StoreKelEvent(ev KelEvent) error
	GetKelEvents(signerAID string) ([]KelEvent, error)
	LastKelSeq(signerAID string) (int, error)

	// StoreTELEvent keeps one event of an issuer's registry log. Storing an
	// event already held is not an error and changes nothing.
	StoreTELEvent(ev TELEvent) error
	// GetTELEvents is every registry event held for an issuer, in the order of
	// the key-log events that anchor them.
	GetTELEvents(issuerAID string) ([]TELEvent, error)
	CountKelEvents(signerAID string) (int, error)

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
