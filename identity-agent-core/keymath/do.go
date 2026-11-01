package keymath

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// Do is keymath's one entry point, as the app reaches it: an operation and a
// JSON request in, a JSON answer out. The phone links it; a desktop runs it as
// the core binary's keymath command, with the request on standard input.
//
// Operations:
//
//	pq_next           {"seed_hex"}               -> {"verkey","digest"}
//	sign_mldsa65      {"seed_hex","msg_b64"}     -> {"sig_b64"}
//	messaging_keyset  {"seed_hex"}               -> {"anchor"}
//	parse_event       {"raw_b64"}                -> Event
//	next_key_digest   {"key"}                    -> {"digest"}
//
// An error never carries any part of the request: a seed, or anything derived
// from one, never reaches an error message, a log or a crash report. The
// request's hex text of a seed is a Go string, which cannot be zeroed; the
// bytes decoded from it are, and the process that ran the command ends.
func Do(op string, request []byte) ([]byte, error) {
	var req struct {
		SeedHex string `json:"seed_hex"`
		MsgB64  string `json:"msg_b64"`
		RawB64  string `json:"raw_b64"`
		Key     string `json:"key"`
	}
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, errors.New("the request is not a JSON object of the fields this operation takes")
	}
	seed := func() ([]byte, error) {
		b, err := hex.DecodeString(req.SeedHex)
		if err != nil || len(b) != ChildSeedBytes {
			zero(b)
			return nil, errors.New("seed_hex is not a 32-byte child seed in hexadecimal")
		}
		return b, nil
	}
	var answer any
	switch op {
	case "pq_next":
		s, err := seed()
		if err != nil {
			return nil, err
		}
		defer zero(s)
		pq, err := PostQuantumNextKey(s)
		if err != nil {
			return nil, errors.New("the post-quantum key could not be derived")
		}
		answer = pq
	case "sign_mldsa65":
		s, err := seed()
		if err != nil {
			return nil, err
		}
		defer zero(s)
		msg, err := base64.StdEncoding.DecodeString(req.MsgB64)
		if err != nil {
			return nil, errors.New("msg_b64 is not standard base64")
		}
		sig, err := SignMLDSA65(s, msg)
		if err != nil {
			return nil, errors.New("the message could not be signed")
		}
		answer = map[string]string{"sig_b64": base64.StdEncoding.EncodeToString(sig)}
	case "messaging_keyset":
		s, err := seed()
		if err != nil {
			return nil, err
		}
		defer zero(s)
		anchor, err := MessagingKeySet(s)
		if err != nil {
			return nil, errors.New("the messaging keyset could not be derived")
		}
		answer = map[string]any{"anchor": anchor}
	case "parse_event":
		raw, err := base64.StdEncoding.Strict().DecodeString(req.RawB64)
		if err != nil {
			return nil, errors.New("raw_b64 is not standard base64")
		}
		ev, err := ParseEvent(raw)
		if err != nil {
			// What is wrong with an event is about the event, never a secret.
			return nil, err
		}
		answer = ev
	case "next_key_digest":
		d, err := NextKeyDigest(req.Key)
		if err != nil {
			return nil, errors.New("there is no key to commit to")
		}
		answer = map[string]string{"digest": d}
	default:
		return nil, errors.New("unknown keymath operation")
	}
	return json.Marshal(answer)
}
