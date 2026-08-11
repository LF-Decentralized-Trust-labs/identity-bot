package keriengine

import (
	"fmt"

	"identity-agent-core/drivers"

	keri "github.com/grapeid/keri-go"
)

// SignPayload refuses, and says why.
//
// This engine holds no private keys. Signing happens where the keys are — on
// the controller device — and an engine able to sign would be an engine that
// had to be handed key material to hold. The Python driver takes exactly this
// position and refuses its own signing endpoint for the same reason.
//
// A call arriving here is a caller routing signing through the backend. The
// caller is what needs fixing.
func (e *Engine) SignPayload(name, dataB64 string) (*drivers.DriverSignResponse, error) {
	return nil, fmt.Errorf("this engine does not sign, and holds no private keys to sign with. "+
		"Private keys stay on the controller device; sign %q there and submit the signature. "+
		"A call reaching here means a code path is routing signing through the backend", name)
}

// VerifySignature checks a signature against a public key.
func (e *Engine) VerifySignature(dataB64, signature, publicKey string) (*drivers.DriverVerifyResponse, error) {
	data, err := decodeB64(dataB64)
	if err != nil {
		return nil, fmt.Errorf("the signed data is not base64: %w", err)
	}
	pub, err := normaliseKey(publicKey, true)
	if err != nil {
		return nil, fmt.Errorf("the public key: %w", err)
	}
	sig, err := signatureBytes(signature)
	if err != nil {
		return nil, err
	}
	// A failed verification is an answer, not an error: the caller asked
	// whether the signature is good and "no" is a valid response. Only a
	// malformed input above is an error.
	valid := keri.VerifySignature(pub, data, sig) == nil
	return &drivers.DriverVerifyResponse{Valid: valid, PublicKey: pub}, nil
}

// signatureBytes accepts a signature in CESR form or as raw base64.
func signatureBytes(signature string) ([]byte, error) {
	if signature == "" {
		return nil, fmt.Errorf("no signature was supplied")
	}
	// CESR: a two-character code and 86 characters of payload.
	if len(signature) == 88 && signature[:2] == keri.CodeEd25519Sig {
		raw, err := keri.MatterRaw(keri.CodeEd25519Sig, signature, 64)
		if err != nil {
			return nil, fmt.Errorf("the signature looks like CESR and does not decode as it: %w", err)
		}
		return raw, nil
	}
	raw, err := decodeB64(signature)
	if err != nil {
		return nil, fmt.Errorf("the signature is neither CESR nor base64: %w", err)
	}
	if len(raw) != 64 {
		return nil, fmt.Errorf("a signature decodes to %d bytes; Ed25519 signatures are 64", len(raw))
	}
	return raw, nil
}

// CesrEncode wraps a raw signature in its CESR form.
func (e *Engine) CesrEncode(rawSigB64 string) (*drivers.DriverCesrEncodeResponse, error) {
	raw, err := decodeB64(rawSigB64)
	if err != nil {
		return nil, fmt.Errorf("the signature is not base64: %w", err)
	}
	if len(raw) != 64 {
		return nil, fmt.Errorf("a signature decodes to %d bytes; Ed25519 signatures are 64", len(raw))
	}
	qb64, err := keri.MatterQB64(keri.CodeEd25519Sig, raw)
	if err != nil {
		return nil, err
	}
	return &drivers.DriverCesrEncodeResponse{CesrSig: qb64, Length: len(qb64)}, nil
}

// ValidateKEL checks a key log and reports what it established.
//
// Prefers the bytes. When the records carry the canonical serialisation and
// the controller's signatures, this is a real verification and delegates to the
// one implementation of it. Field order is part of an event and a re-encoded
// event digests to something else, so those bytes are the only thing a
// signature or an identifier can be checked against — a parsed log cannot be
// turned back into them.
//
// Falls back to walking the parsed events when they are absent. That check is
// worth something — it catches a log with a gap, a repeat, or events belonging
// to somebody else — but it proves nothing about authorship, and it says so
// rather than reporting a log it did not verify as verified.
func (e *Engine) ValidateKEL(aid string, events []map[string]interface{}) (*drivers.DriverValidateKELResponse, error) {
	if len(events) == 0 {
		return &drivers.DriverValidateKELResponse{
			KelVerified:      false,
			ValidationErrors: []string{"an empty key log establishes nothing; this is not a verdict about the identity"},
		}, nil
	}

	if in, ok := drivers.ValidateKELInputFromRecords(aid, events); ok {
		return drivers.ValidateKELFromBytes(in)
	}

	out := &drivers.DriverValidateKELResponse{}
	var problems []string

	// Chain the events by digest and sequence number. This is what a parsed
	// log can still prove: that each event names the one before it, that the
	// numbering has no gaps, and that every event belongs to the identity
	// claimed. It cannot prove any of them was signed.
	prior := ""
	for i, ev := range events {
		ident, _ := ev["i"].(string)
		if aid != "" && ident != aid {
			problems = append(problems, fmt.Sprintf("event %d belongs to %s, not %s", i, ident, aid))
		}
		sn, err := hexSN(ev["s"])
		if err != nil {
			problems = append(problems, fmt.Sprintf("event %d has an unreadable sequence number: %v", i, err))
		} else if sn != i {
			problems = append(problems, fmt.Sprintf("event %d is numbered %d; a log with a gap or a "+
				"repeat is not one history", i, sn))
		}
		if i > 0 {
			if p, _ := ev["p"].(string); p != prior {
				problems = append(problems, fmt.Sprintf("event %d names %q as its predecessor, but "+
					"event %d digests to %q", i, p, i-1, prior))
			}
		}
		prior, _ = ev["d"].(string)

		if keys, ok := ev["k"].([]interface{}); ok && len(keys) > 0 {
			if k, ok := keys[0].(string); ok {
				out.CurrentPublicKey = k
			}
		}
	}

	out.EventsValidated = len(events)
	out.ValidationErrors = problems

	// The chain holding is not authorship being proven, and this path cannot
	// establish the second: the parsed form carries no signature to check.
	//
	// So KelVerified stays false here however clean the log looks. It is the
	// boolean every trust gate reads before letting a log establish a key, and
	// a consistent chain is something a forger produces as easily as anyone
	// else — they wrote every event in it. What this path can honestly report
	// is that the log holds together.
	out.LogSound = len(problems) == 0
	out.KelVerified = false
	out.EventsUnsigned = len(events)
	if out.LogSound {
		out.ValidationErrors = []string{
			"the chain is consistent; no signature was checked, because signatures verify " +
				"against canonical event bytes and this log was supplied in parsed form",
		}
	}
	return out, nil
}

func hexSN(v interface{}) (int, error) {
	s, ok := v.(string)
	if !ok {
		return 0, fmt.Errorf("expected a hex string, got %T", v)
	}
	var n int
	if _, err := fmt.Sscanf(s, "%x", &n); err != nil {
		return 0, err
	}
	return n, nil
}

// SubmitReceipt records a witness receipt for an event and reports whether the
// event has now been receipted by enough witnesses.
func (e *Engine) SubmitReceipt(req *drivers.DriverSubmitReceiptRequest) (*drivers.DriverSubmitReceiptResponse, error) {
	if req == nil || req.EventSAID == "" {
		return nil, fmt.Errorf("a receipt has to name the event it receipts")
	}
	if req.WitnessAID == "" {
		return nil, fmt.Errorf("a receipt has to name the witness that produced it")
	}

	resp := &drivers.DriverSubmitReceiptResponse{}

	// A witness not on the designated list is refused rather than counted.
	// Counting one would let anybody who can produce a signature contribute to
	// a threshold, which is the entire protection the threshold provides.
	if len(req.TrustedWitnesses) > 0 {
		trusted := false
		for _, w := range req.TrustedWitnesses {
			if w == req.WitnessAID {
				trusted = true
				break
			}
		}
		if !trusted {
			resp.Errors = append(resp.Errors, fmt.Sprintf(
				"%s is not a designated witness for this event; its receipt is not counted",
				req.WitnessAID))
			return resp, nil
		}
	}

	// The signature is over the event's identifier and must verify against the
	// witness's own key.
	if req.WitnessPublicKey != "" && req.CesrSignature != "" {
		pub, err := normaliseKey(req.WitnessPublicKey, false)
		if err != nil {
			return nil, fmt.Errorf("the witness key: %w", err)
		}
		sig, err := signatureBytes(req.CesrSignature)
		if err != nil {
			return nil, err
		}
		if err := keri.VerifySignature(pub, []byte(req.EventSAID), sig); err != nil {
			resp.Errors = append(resp.Errors, fmt.Sprintf(
				"the receipt from %s does not verify against its key, so it is not a receipt "+
					"that witness produced", req.WitnessAID))
			return resp, nil
		}
	} else {
		resp.Errors = append(resp.Errors, "the receipt carried no signature to check, so it "+
			"records only that a receipt was claimed")
	}

	e.state.mu.Lock()
	existing := e.state.receipts[req.EventSAID]
	// One witness counts once. Without this a single witness could meet any
	// threshold by submitting repeatedly.
	for _, r := range existing {
		if r.WitnessAID == req.WitnessAID {
			e.state.mu.Unlock()
			resp.Accepted = true
			resp.ReceiptCount = len(existing)
			resp.ThresholdMet = req.Threshold > 0 && len(existing) >= req.Threshold
			return resp, nil
		}
	}
	existing = append(existing, receipt{
		WitnessAID: req.WitnessAID,
		PublicKey:  req.WitnessPublicKey,
		CesrSig:    req.CesrSignature,
	})
	e.state.receipts[req.EventSAID] = existing
	e.state.mu.Unlock()

	resp.Accepted = true
	resp.ReceiptCount = len(existing)
	resp.ThresholdMet = req.Threshold > 0 && len(existing) >= req.Threshold
	return resp, nil
}

// GenerateMultisigEvent builds an event for a group identity.
//
// Stateless: the group's members hold the state, and this produces the event
// they each sign. Nothing is recorded here, because a group event that only one
// member has agreed to is not yet the group's.
func (e *Engine) GenerateMultisigEvent(aids []string, threshold int, currentKeys, nextKeys []string, eventType string) (*drivers.DriverMultisigResponse, error) {
	if len(currentKeys) == 0 {
		return nil, fmt.Errorf("a group event needs the keys it is controlled by")
	}
	if threshold <= 0 {
		return nil, fmt.Errorf("a threshold of %d cannot be met by any number of signatures", threshold)
	}
	if threshold > len(currentKeys) {
		return nil, fmt.Errorf("a threshold of %d over %d keys can never be met",
			threshold, len(currentKeys))
	}

	keys := make([]string, 0, len(currentKeys))
	for i, k := range currentKeys {
		n, err := normaliseKey(k, true)
		if err != nil {
			return nil, fmt.Errorf("member key %d: %w", i, err)
		}
		keys = append(keys, n)
	}
	// The next keys arrive as keys and are committed to as digests. Publishing
	// them directly would forfeit pre-rotation entirely: the successor would be
	// public from the moment the group was founded.
	digests := make([]string, 0, len(nextKeys))
	for i, k := range nextKeys {
		n, err := normaliseKey(k, true)
		if err != nil {
			return nil, fmt.Errorf("next member key %d: %w", i, err)
		}
		d, err := keri.NextDigest(n)
		if err != nil {
			return nil, err
		}
		digests = append(digests, d)
	}

	switch eventType {
	case "icp", "":
		raw, err := keri.BuildInception(keri.InceptionInput{
			Keys:        keys,
			NextDigests: digests,
			Isith:       thresholdJSON(fmt.Sprintf("%x", threshold)),
			Derivation:  "self-addressing",
		})
		if err != nil {
			return nil, fmt.Errorf("building the group inception: %w", err)
		}
		ev, err := keri.ParseEvent(raw)
		if err != nil {
			return nil, err
		}
		return &drivers.DriverMultisigResponse{
			RawBytesB64: b64(raw),
			Said:        ev.SAID,
			Pre:         ev.Identifier,
			EventType:   "icp",
			Size:        len(raw),
		}, nil
	default:
		return nil, fmt.Errorf("%q is not a group event type this engine builds; it builds "+
			"inception events, which is what a group needs before it has a log to extend", eventType)
	}
}

// ValidateKELBytes checks a log from the bytes it was published as.
//
// Delegates to the one implementation both engines share. Validation is
// arithmetic over bytes the caller already holds — it reaches out to nothing
// and keeps no state — so a copy of it here could only diverge from the other,
// on the check that decides whether a stranger is who they claim to be.
func (e *Engine) ValidateKELBytes(in drivers.ValidateKELInput) (*drivers.DriverValidateKELResponse, error) {
	return drivers.ValidateKELFromBytes(in)
}
