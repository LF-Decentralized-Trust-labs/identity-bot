package server

import (
	"encoding/json"
	"fmt"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/iacrypto"
)

// signedInceptionKEL is the key event log of an identity that has only ever had
// its inception event, signed and framed as a CESR stream, which is how a
// service that is asked to trust a key checks it belongs to the identifier.
//
// The engine forgets an identity when the Identity Agent restarts, and what is
// kept of the event is its parsed form. That cannot simply be re-serialised —
// field order is part of the event — so the event is rebuilt from its fields
// with the KERI library and then checked: an identifier is the digest of its
// own inception event, so a rebuild that produces the same identifier is the
// same event, byte for byte. Anything else is refused rather than sent.
func signedInceptionKEL(aid string, kel []map[string]interface{}, seed []byte) ([]byte, error) {
	if len(kel) != 1 {
		return nil, fmt.Errorf("%s has %d key events; only an identity that has never rotated can be rebuilt this way", aid, len(kel))
	}
	ev := kel[0]
	if t, _ := ev["t"].(string); t != "icp" {
		return nil, fmt.Errorf("%s's first event is %q, not an inception", aid, t)
	}
	if c, _ := ev["c"].([]interface{}); len(c) > 0 {
		return nil, fmt.Errorf("%s's inception declares configuration traits, which cannot be rebuilt here", aid)
	}
	bt, _ := ev["bt"].(string)
	t, err := iacrypto.ParseHexCount(bt)
	if err != nil {
		return nil, fmt.Errorf("%s's witness threshold %v is unreadable", aid, ev["bt"])
	}
	in := keri.InceptionInput{
		Keys:        stringsOf(ev["k"]),
		NextDigests: stringsOf(ev["n"]),
		Witnesses:   stringsOf(ev["b"]),
		Toad:        &t,
		Isith:       rawJSON(ev["kt"]),
		Nsith:       rawJSON(ev["nt"]),
		// The library's default for a single key is to name the identity by the
		// key itself. A recorded identity named by a digest of its inception was
		// made the other way, and must be rebuilt the same way.
		Derivation: "self-addressing",
	}
	if keys := stringsOf(ev["k"]); len(keys) == 1 && keys[0] == aid {
		in.Derivation = "basic"
	}
	if a, ok := ev["a"].([]interface{}); ok {
		for _, item := range a {
			in.Data = append(in.Data, rawJSON(item))
		}
	}
	event, err := keri.BuildInception(in)
	if err != nil {
		return nil, fmt.Errorf("rebuild %s's inception: %w", aid, err)
	}
	parsed, err := keri.ParseEvent(event)
	if err != nil {
		return nil, err
	}
	if parsed.Identifier != aid {
		return nil, fmt.Errorf("the rebuilt inception establishes %s, not %s, so it is not the same event", parsed.Identifier, aid)
	}
	signer, err := keri.NewSoftwareSigner(seed, true)
	if err != nil {
		return nil, err
	}
	signed, err := keri.SignEvent(event, signer)
	if err != nil {
		return nil, fmt.Errorf("sign %s's inception: %w", aid, err)
	}
	return keri.ExportKEL([][]byte{signed.Message})
}

func stringsOf(v interface{}) []string {
	items, _ := v.([]interface{})
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func rawJSON(v interface{}) json.RawMessage {
	raw, _ := json.Marshal(v)
	return raw
}
