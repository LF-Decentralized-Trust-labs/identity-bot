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

	SaveIssuedReceipt(r IssuedReceipt) error
	GetFinalization(eventSAID string) (*FinalizationState, error)
	SaveFinalization(f FinalizationState) error

	CountWitnessingFor() (int, error)
	RecordSelfHealAttempt(contactAID string, at string) error
	LastSelfHealAttempt(contactAID string) (string, error)
	CountSelfHealAttemptsSince(since string) (int, error)
}
