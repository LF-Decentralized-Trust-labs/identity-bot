package didwebs

import "time"

// ResolvedDID is the result of a did:webs resolution pass.
type ResolvedDID struct {
	DID              string
	AID              string
	Host             string
	DidJSON          map[string]interface{}
	Events           []map[string]interface{}
	DidKeystateSeq   int
	CesrKeystateSeq  int
	CesrComplete     bool
	ReplayVerified   bool
	ReplayErrors     []string
	CurrentPublicKey string
	FetchedAt        time.Time
}

// FetchStatus describes artifact availability.
type FetchStatus int

const (
	FetchOK FetchStatus = iota
	FetchNotFound
	FetchPartial
	FetchSeqMismatch
	FetchError
)
