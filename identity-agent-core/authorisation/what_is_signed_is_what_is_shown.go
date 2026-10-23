package authorisation

// What the device holding an identity's key is shown before it signs.
//
// An Identity Agent that does not hold its identity's key asks the device that
// does to sign the interaction that anchors a grant. That device signs bytes
// it did not build, sent by an Identity Agent whose database somebody else may
// be able to write. So it is never shown anything that Identity Agent wrote
// about them: it is sent the credential, its issuance event and the
// interaction, checks that the interaction anchors exactly that issuance and
// the issuance names exactly that credential, and shows what the credential
// itself says. Signing then grants what was shown and nothing else.
//
// The device must also check that the interaction extends its identity's key
// log as it holds it: that Prior is its tip and SN the place after it. The
// device's own core does that, as the route that runs this function.

import (
	"encoding/json"
	"fmt"
	"strings"

	"identity-agent-core/iacrypto"
	"identity-agent-core/schemas"

	keri "github.com/grapeid/keri-go"
)

// ToSign is what signing an interaction grants, read from what it anchors.
type ToSign struct {
	// Kind is "machine", "ai_agent" or "registry".
	Kind string `json:"kind"`
	// Issuer is the identity whose key log the interaction extends, at SN,
	// after Prior.
	Issuer string `json:"issuer"`
	SN     int    `json:"sn"`
	Prior  string `json:"prior"`

	Credential string `json:"credential,omitempty"`
	Registry   string `json:"registry,omitempty"`
	// Holder is who the grant is to: the machine's identifier, or the AI
	// agent's.
	Holder string `json:"holder,omitempty"`
	Name   string `json:"name,omitempty"`
	// PublicKey and KeyFingerprint are the machine's key, and the short form
	// of it the owner compares with the one shown when the machine paired.
	PublicKey      string          `json:"public_key,omitempty"`
	KeyFingerprint string          `json:"key_fingerprint,omitempty"`
	Grade          string          `json:"grade,omitempty"`
	Signer         string          `json:"signer,omitempty"`
	ValidUntil     string          `json:"valid_until,omitempty"`
	Capabilities   []string        `json:"capabilities,omitempty"`
	Limits         json.RawMessage `json:"resource_constraints,omitempty"`
	// Revokes is set where signing withdraws the grant shown, rather than
	// issuing it.
	Revokes bool `json:"revokes,omitempty"`
}

// KeyFingerprint is a machine key's short form: eight characters of its
// digest, in two groups, the same wherever it is shown.
func KeyFingerprint(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	d := iacrypto.Blake3QB64Must([]byte("key-fingerprint/v1\n" + key))
	return strings.ToUpper(d[1:5] + "-" + d[5:9])
}

// anchoringSeal checks that ixn is a well-formed interaction of issuer whose
// one seal names subject at place 0 with digest tel, and returns it parsed.
func anchoringSeal(ixnRaw []byte, issuer, subject, sn, tel string) (*keri.Event, error) {
	if err := keri.ValidateEvent(ixnRaw); err != nil {
		return nil, fmt.Errorf("the interaction is not what it says it is: %w", err)
	}
	ixn, err := keri.ParseEvent(ixnRaw)
	if err != nil {
		return nil, err
	}
	if ixn.Ilk != "ixn" || ixn.Identifier != issuer {
		return nil, fmt.Errorf("the event to sign is not an interaction of %s", issuer)
	}
	var body struct {
		A []map[string]interface{} `json:"a"`
	}
	if err := json.Unmarshal(ixnRaw, &body); err != nil {
		return nil, err
	}
	if len(body.A) != 1 {
		return nil, fmt.Errorf("the interaction anchors %d things, where it must anchor exactly what is shown", len(body.A))
	}
	seal := body.A[0]
	if seal["i"] != subject || seal["s"] != sn || seal["d"] != tel || len(seal) != 3 {
		return nil, fmt.Errorf("the interaction does not anchor what is shown")
	}
	return ixn, nil
}

// WhatSigningGrants checks that ixn anchors exactly the issuance iss of the
// credential acdc, and says what signing it grants, read from the credential.
func WhatSigningGrants(ixnRaw, issRaw, acdcRaw []byte) (*ToSign, error) {
	cred, err := keri.VerifyCredential(acdcRaw)
	if err != nil {
		return nil, fmt.Errorf("the credential does not verify against its own identifier: %w", err)
	}
	iss, err := keri.VerifyTELEvent(issRaw)
	if err != nil {
		return nil, fmt.Errorf("the issuance event does not verify: %w", err)
	}
	if iss.Ilk != "iss" || iss.Subject != cred.SAID || iss.Registry != cred.Registry {
		return nil, fmt.Errorf("the issuance event is not of this credential")
	}
	ixn, err := anchoringSeal(ixnRaw, cred.Issuer, cred.SAID, "0", iss.SAID)
	if err != nil {
		return nil, err
	}
	return grantShown(cred, ixn)
}

// WhatSigningRevokes checks that ixn anchors exactly the revocation rev of the
// credential acdc, and says what signing it withdraws, read from the
// credential.
func WhatSigningRevokes(ixnRaw, revRaw, acdcRaw []byte) (*ToSign, error) {
	cred, err := keri.VerifyCredential(acdcRaw)
	if err != nil {
		return nil, fmt.Errorf("the credential does not verify against its own identifier: %w", err)
	}
	rev, err := keri.VerifyTELEvent(revRaw)
	if err != nil {
		return nil, fmt.Errorf("the revocation does not verify: %w", err)
	}
	if rev.Ilk != "rev" || rev.Subject != cred.SAID || rev.Registry != cred.Registry {
		return nil, fmt.Errorf("the revocation is not of this credential")
	}
	ixn, err := anchoringSeal(ixnRaw, cred.Issuer, cred.SAID, "1", rev.SAID)
	if err != nil {
		return nil, err
	}
	out, err := grantShown(cred, ixn)
	if err != nil {
		return nil, err
	}
	out.Revokes = true
	return out, nil
}

// grantShown is what a grant says, read from the credential.
func grantShown(cred *keri.Credential, ixn *keri.Event) (*ToSign, error) {
	out := &ToSign{Issuer: cred.Issuer, SN: int(ixn.SN), Prior: ixn.PriorSAID, Credential: cred.SAID, Registry: cred.Registry}
	var a map[string]json.RawMessage
	if err := json.Unmarshal(cred.Attributes, &a); err != nil {
		return nil, fmt.Errorf("the credential's attributes are unreadable")
	}
	str := func(k string) string { return strings.TrimSpace(stringOf(a[k])) }
	out.Holder, out.Name, out.ValidUntil = str("i"), str("name"), str("valid_until")
	switch cred.SchemaSAID {
	case schemas.ControllerGrant.Schema.SAID:
		out.Kind = "machine"
		out.Name = firstNonEmpty(str("label"), out.Name)
		out.PublicKey, out.Grade, out.Signer = str("public_key"), str("grade"), str("signer")
		out.KeyFingerprint = KeyFingerprint(out.PublicKey)
	case schemas.AIAgentGrant.Schema.SAID:
		out.Kind = "ai_agent"
		_ = json.Unmarshal(a["capabilities"], &out.Capabilities)
		if rc, ok := a["resource_constraints"]; ok {
			out.Limits = rc
		}
	default:
		return nil, fmt.Errorf("the credential is not a grant this device is asked to sign")
	}
	if out.Holder == "" || out.Holder != cred.Recipient && cred.Recipient != "" {
		return nil, fmt.Errorf("the credential does not say plainly who it grants")
	}
	return out, nil
}

// WhatSigningRegisters checks that ixn anchors exactly the registry inception
// vcp, and says so.
func WhatSigningRegisters(ixnRaw, vcpRaw []byte) (*ToSign, error) {
	vcp, err := keri.VerifyTELEvent(vcpRaw)
	if err != nil {
		return nil, fmt.Errorf("the registry inception does not verify: %w", err)
	}
	if vcp.Ilk != "vcp" {
		return nil, fmt.Errorf("the event is not a registry inception")
	}
	var body struct {
		I  string   `json:"i"`
		II string   `json:"ii"`
		C  []string `json:"c"`
		BT string   `json:"bt"`
		B  []string `json:"b"`
	}
	if err := json.Unmarshal(vcpRaw, &body); err != nil {
		return nil, err
	}
	// Only the registry this agent makes: no backers, so its state is read
	// from the issuer's own key log. Anything else would put parties the owner
	// is not shown in charge of what the registry says.
	traitsOK := len(body.C) == 0 || (len(body.C) == 1 && body.C[0] == "NB")
	if len(body.B) != 0 || (body.BT != "" && body.BT != "0") || !traitsOK {
		return nil, fmt.Errorf("the registry is not one with no backers, which is the only kind signed here")
	}
	registry := firstNonEmpty(body.I, vcp.SAID)
	if body.II == "" {
		return nil, fmt.Errorf("the registry inception names no issuer")
	}
	ixn, err := anchoringSeal(ixnRaw, body.II, registry, "0", vcp.SAID)
	if err != nil {
		return nil, err
	}
	return &ToSign{Kind: "registry", Issuer: body.II, SN: int(ixn.SN), Prior: ixn.PriorSAID, Registry: registry}, nil
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}
