package iacrypto

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

const (
	keriVersionMajor = 1
	keriVersionMinor = 0
	keriVersionKind  = "JSON"
	saidDummyLen     = 44 // Blake3_256 fs — Serder.Dummy × fs
)

// anchorSeal is the IA-HYBRID-1 typed seal in standard a anchor.
type anchorSeal struct {
	Ia string   `json:"ia"`
	Ka []string `json:"ka"`
}

// icpWire matches keri 1.1.17 SerderKERI icp field order (v,t,d,i,s,kt,k,nt,n,bt,b,c,a).
type icpWire struct {
	V  string        `json:"v"`
	T  string        `json:"t"`
	D  string        `json:"d"`
	I  string        `json:"i"`
	S  string        `json:"s"`
	Kt string        `json:"kt"`
	K  []string      `json:"k"`
	Nt string        `json:"nt"`
	N  []string      `json:"n"`
	Bt string        `json:"bt"`
	B  []interface{} `json:"b"`
	C  []interface{} `json:"c"`
	A  []anchorSeal  `json:"a"`
	// Di names the delegator, and exists only on a delegated inception.
	//
	// Last, and omitted when empty, because that is where this field sits in
	// the event a delegated inception produces and because an ordinary
	// inception has to keep serializing to exactly the bytes it did before —
	// the identifier is derived from those bytes, so a field appearing in them
	// would change every identifier already created.
	Di string `json:"di,omitempty"`
}

var keriVersionRE = regexp.MustCompile(`KERI[0-9a-f][0-9a-f]JSON[0-9a-f]{6}_`)

func versify(size int) string {
	return fmt.Sprintf("KERI%x%x%s%06x_", keriVersionMajor, keriVersionMinor, keriVersionKind, size)
}

func patchVersionSize(raw []byte) ([]byte, error) {
	loc := keriVersionRE.FindIndex(raw)
	if loc == nil {
		return nil, fmt.Errorf("keri version string not found in raw")
	}
	vs := versify(len(raw))
	if len(vs) != loc[1]-loc[0] {
		return nil, fmt.Errorf("version string length mismatch: got %d want %d", len(vs), loc[1]-loc[0])
	}
	out := make([]byte, len(raw))
	copy(out, raw)
	copy(out[loc[0]:loc[1]], []byte(vs))
	return out, nil
}

func serializeICPWire(w icpWire) ([]byte, error) {
	w.V = versify(0)
	raw, err := json.Marshal(w)
	if err != nil {
		return nil, err
	}
	return patchVersionSize(raw)
}

// makifyICPWire applies keri 1.1.17 SerderKERI makify (dummy d/i, Blake3, same digest).
func makifyICPWire(w icpWire) (icpWire, []byte, error) {
	dummy := strings.Repeat("#", saidDummyLen)
	dummied := w
	dummied.D = dummy
	dummied.I = dummy

	raw, err := serializeICPWire(dummied)
	if err != nil {
		return icpWire{}, nil, err
	}
	dig, err := Blake3QB64(raw)
	if err != nil {
		return icpWire{}, nil, err
	}

	final := w
	final.D = dig
	final.I = dig
	raw, err = serializeICPWire(final)
	if err != nil {
		return icpWire{}, nil, err
	}
	final.V = versify(len(raw))
	return final, raw, nil
}
