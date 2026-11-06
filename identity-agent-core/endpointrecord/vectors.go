package endpointrecord

import (
	_ "embed"
	"encoding/json"
)

// vectors are records, the bytes each is signed over, whether each verifies
// and why not, the origins that are in their one spelling and those that are
// not, and which of two records replaces the other. It is the file another
// implementation tests itself against. It ships inside this module so a Go
// implementation reads the same file instead of keeping a copy.
//
//go:embed endpoint-record-vectors.json
var vectors []byte

// VectorSet is the published set of endpoint record vectors.
type VectorSet struct {
	About string `json:"about"`
	// SeedHex is the seed of the key that signs the valid records, and
	// PublicKey that key as a CESR qb64 verifier. OtherPublicKey is a key
	// nobody here signs with.
	SeedHex        string `json:"seed_hex"`
	PublicKey      string `json:"public_key"`
	OtherPublicKey string `json:"other_public_key"`
	// NextSeedHex and NextPublicKey are the key the identifier rotated to: the
	// key its verified key log names after the rotation, where PublicKey is the
	// one it names before.
	NextSeedHex   string `json:"next_seed_hex"`
	NextPublicKey string `json:"next_public_key"`
	// Now is the verifier's clock for every record below.
	Now     string         `json:"now"`
	Records []RecordVector `json:"records"`
	Origins []OriginVector `json:"origins"`
	// Addresses are what a client was pointed at and the origin it signs a
	// request for (or a record names), or "" where it has none.
	Addresses []AddressVector `json:"addresses"`
	Ordering  []OrderVector   `json:"ordering"`
	// Requests are the strings a controller signs for a request, the second
	// form and the third, which names the origin the request is sent to.
	Requests []RequestVector `json:"requests"`
}

// RequestVector is the string a controller signs for a request, from the parts
// it is made of. An empty Origin is the second form (IA-CONTROLLER-REQ-V2); a
// request that names one is the third (IA-CONTROLLER-REQ-V3), the origin on a
// line of its own after the Identity Agent. Level, MeasuredAt and Score are what
// the machine vouched for about how the person was authenticated, empty and 0
// when it vouched for nothing.
type RequestVector struct {
	Name          string `json:"name"`
	Controller    string `json:"controller"`
	IdentityAgent string `json:"identity_agent"`
	Origin        string `json:"origin"`
	Method        string `json:"method"`
	Path          string `json:"path"`
	Timestamp     string `json:"timestamp"`
	Level         string `json:"level"`
	MeasuredAt    string `json:"measured_at"`
	Score         int    `json:"score"`
	BodyDigest    string `json:"body_digest"`
	// Signed is the string, lines joined by a line feed.
	Signed string `json:"signed"`
}

// RecordVector is one record as it arrives, checked against Key.
type RecordVector struct {
	Name   string         `json:"name"`
	Record map[string]any `json:"record"`
	// Key is "public_key", "other_public_key" or "next_public_key".
	Key string `json:"key"`
	// Canonical is the bytes the signature is over, where the record has the
	// form to have any.
	Canonical string `json:"canonical,omitempty"`
	Valid     bool   `json:"valid"`
	Why       string `json:"why,omitempty"`
	// MaxAgeDays is the optional age limit the record is checked with. Absent
	// means none, which is the default: a record does not expire.
	MaxAgeDays int `json:"max_age_days,omitempty"`
}

// OriginVector is an origin and whether it is in its one spelling.
type OriginVector struct {
	Origin string `json:"origin"`
	OK     bool   `json:"ok"`
}

// AddressVector is an address and the origin it stands for, "" when it is not
// the address of an http or https host.
type AddressVector struct {
	Address string `json:"address"`
	Origin  string `json:"origin"`
}

// OrderVector says whether record A replaces record B.
type OrderVector struct {
	Name   string `json:"name"`
	AAID   string `json:"a_aid"`
	AIssue string `json:"a_issued"`
	BAID   string `json:"b_aid"`
	BIssue string `json:"b_issued"`
	Newer  bool   `json:"newer"`
}

// Vectors returns the published vectors.
func Vectors() (VectorSet, error) {
	var v VectorSet
	err := json.Unmarshal(vectors, &v)
	return v, err
}
