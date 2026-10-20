// Package driverfake provides a configurable in-memory KERI engine for tests.
//
// A test sets only the methods its code path exercises, through the matching
// func field, and injects the Engine as the server's drivers.KeriEngine. Every
// method left unset fails loudly rather than returning a zero value, so a test
// can never pass because a call it did not anticipate quietly succeeded.
//
// It performs no cryptography: it returns exactly what the test configures. It
// exists so a handler can be tested against chosen KERI answers — a forged key
// log, a specific anchored owner, a verified credential — that a real engine
// would not produce. Behaviour that needs a real engine uses keriengine.New().
package driverfake

import (
	"fmt"

	"identity-agent-core/drivers"
)

// Engine is a drivers.KeriEngine backed by per-method func fields.
type Engine struct {
	InceptFunc                     func(req drivers.InceptionRequest) (*drivers.DriverInceptionResponse, error)
	CreateInceptionFunc            func(publicKey, nextPublicKey string) (*drivers.DriverInceptionResponse, error)
	CreateInceptionNamedFunc       func(publicKey, nextPublicKey, name string) (*drivers.DriverInceptionResponse, error)
	CreateOwnedInceptionFunc       func(publicKey, nextPublicKey, name, ownerAID string) (*drivers.DriverInceptionResponse, error)
	CreateDelegatedInceptionFunc   func(publicKey, nextPublicKey, name, delegatorName string) (*drivers.DriverDelegatedInceptionResponse, error)
	ReinstateDelegatedIdentityFunc func(publicKey, nextPublicKey, name, delegatorName string) (*drivers.DriverDelegatedInceptionResponse, error)
	RotateAidFunc                  func(name, newPublicKey, newNextPublicKey string) (*drivers.DriverRotationResponse, error)
	RotateAidWithAnchorFunc        func(name, newPublicKey, newNextPublicKey string, anchorData []interface{}) (*drivers.DriverRotationResponse, error)
	RotateFunc                     func(req drivers.RotationRequest) (*drivers.DriverRotationResponse, error)
	CreateHybridInceptionFunc      func(synthetic bool, name string) (*drivers.DriverHybridInceptionResponse, error)
	RotateToMultisigFunc           func(name string, keys, nextKeyDigests []string, isith, nsith string, anchorData []interface{}) (*drivers.DriverRotationResponse, error)
	GenerateMultisigEventFunc      func(aids []string, threshold int, currentKeys, nextKeys []string, eventType string) (*drivers.DriverMultisigResponse, error)
	InteractFunc                   func(name string, data []interface{}) (*drivers.DriverInteractResponse, error)
	GetKelFunc                     func(name string) (*drivers.DriverKelResponse, error)
	ValidateKELFunc                func(aid string, events []map[string]interface{}) (*drivers.DriverValidateKELResponse, error)
	ValidateKELBytesFunc           func(in drivers.ValidateKELInput) (*drivers.DriverValidateKELResponse, error)
	SignPayloadFunc                func(name, dataB64 string) (*drivers.DriverSignResponse, error)
	VerifySignatureFunc            func(dataB64, signature, publicKey string) (*drivers.DriverVerifyResponse, error)
	CesrEncodeFunc                 func(rawSigB64 string) (*drivers.DriverCesrEncodeResponse, error)
	FormatCredentialFunc           func(claims map[string]interface{}, schemaSaid, issuerAid string) (*drivers.DriverFormatCredentialResponse, error)
	InceptRegistryFunc             func(name string) (*drivers.DriverRegistryInceptResponse, error)
	IssueCredentialFunc            func(name string, claims map[string]interface{}, schemaSaid, holderAid string, edges map[string]interface{}) (*drivers.DriverIssueCredentialResponse, error)
	IssueCredentialInRegistryFunc  func(name string, claims map[string]interface{}, schemaSaid, holderAid string, edges map[string]interface{}, registrySaid string) (*drivers.DriverIssueCredentialResponse, error)
	RevokeCredentialFunc           func(name, acdcSaid, registrySaid, issSaid string) (*drivers.DriverRevokeCredentialResponse, error)
	VerifyCredentialFunc           func(req *drivers.DriverVerifyCredentialRequest) (*drivers.DriverVerifyCredentialResponse, error)
	PresentCredentialFunc          func(acdcSaid, holderAid, issuerAid, schemaSaid string) (*drivers.DriverPresentCredentialResponse, error)
	SubmitReceiptFunc              func(req *drivers.DriverSubmitReceiptRequest) (*drivers.DriverSubmitReceiptResponse, error)
	ResolveOobiFunc                func(url string) (*drivers.DriverResolveOobiResponse, error)
	EndpointLocationFunc           func(req *drivers.DriverEndpointLocationRequest) (*drivers.DriverEndpointResponse, error)
	StartFunc                      func() error
	StopFunc                       func()
	GetStatusFunc                  func() (*drivers.DriverStatus, error)
	ReloadIdentityFunc             func(req *drivers.DriverReloadIdentityRequest) (*drivers.DriverReloadIdentityResponse, error)
}

var _ drivers.KeriEngine = (*Engine)(nil)

func unset(method string) error {
	return fmt.Errorf("driverfake: %s called but not configured for this test", method)
}

func (e *Engine) Incept(req drivers.InceptionRequest) (*drivers.DriverInceptionResponse, error) {
	if e.InceptFunc == nil {
		return nil, unset("Incept")
	}
	return e.InceptFunc(req)
}

func (e *Engine) CreateInception(publicKey, nextPublicKey string) (*drivers.DriverInceptionResponse, error) {
	if e.CreateInceptionFunc == nil {
		return nil, unset("CreateInception")
	}
	return e.CreateInceptionFunc(publicKey, nextPublicKey)
}

func (e *Engine) CreateInceptionNamed(publicKey, nextPublicKey, name string) (*drivers.DriverInceptionResponse, error) {
	if e.CreateInceptionNamedFunc == nil {
		return nil, unset("CreateInceptionNamed")
	}
	return e.CreateInceptionNamedFunc(publicKey, nextPublicKey, name)
}

func (e *Engine) CreateOwnedInception(publicKey, nextPublicKey, name, ownerAID string) (*drivers.DriverInceptionResponse, error) {
	if e.CreateOwnedInceptionFunc == nil {
		return nil, unset("CreateOwnedInception")
	}
	return e.CreateOwnedInceptionFunc(publicKey, nextPublicKey, name, ownerAID)
}

func (e *Engine) CreateDelegatedInception(publicKey, nextPublicKey, name, delegatorName string) (*drivers.DriverDelegatedInceptionResponse, error) {
	if e.CreateDelegatedInceptionFunc == nil {
		return nil, unset("CreateDelegatedInception")
	}
	return e.CreateDelegatedInceptionFunc(publicKey, nextPublicKey, name, delegatorName)
}

func (e *Engine) ReinstateDelegatedIdentity(publicKey, nextPublicKey, name, delegatorName string) (*drivers.DriverDelegatedInceptionResponse, error) {
	if e.ReinstateDelegatedIdentityFunc == nil {
		return nil, unset("ReinstateDelegatedIdentity")
	}
	return e.ReinstateDelegatedIdentityFunc(publicKey, nextPublicKey, name, delegatorName)
}

func (e *Engine) RotateAid(name, newPublicKey, newNextPublicKey string) (*drivers.DriverRotationResponse, error) {
	if e.RotateAidFunc == nil {
		return nil, unset("RotateAid")
	}
	return e.RotateAidFunc(name, newPublicKey, newNextPublicKey)
}

func (e *Engine) RotateAidWithAnchor(name, newPublicKey, newNextPublicKey string, anchorData []interface{}) (*drivers.DriverRotationResponse, error) {
	if e.RotateAidWithAnchorFunc == nil {
		return nil, unset("RotateAidWithAnchor")
	}
	return e.RotateAidWithAnchorFunc(name, newPublicKey, newNextPublicKey, anchorData)
}

func (e *Engine) Rotate(req drivers.RotationRequest) (*drivers.DriverRotationResponse, error) {
	if e.RotateFunc == nil {
		return nil, unset("Rotate")
	}
	return e.RotateFunc(req)
}

func (e *Engine) CreateHybridInception(synthetic bool, name string) (*drivers.DriverHybridInceptionResponse, error) {
	if e.CreateHybridInceptionFunc == nil {
		return nil, unset("CreateHybridInception")
	}
	return e.CreateHybridInceptionFunc(synthetic, name)
}

func (e *Engine) RotateToMultisig(name string, keys, nextKeyDigests []string, isith, nsith string, anchorData []interface{}) (*drivers.DriverRotationResponse, error) {
	if e.RotateToMultisigFunc == nil {
		return nil, unset("RotateToMultisig")
	}
	return e.RotateToMultisigFunc(name, keys, nextKeyDigests, isith, nsith, anchorData)
}

func (e *Engine) GenerateMultisigEvent(aids []string, threshold int, currentKeys, nextKeys []string, eventType string) (*drivers.DriverMultisigResponse, error) {
	if e.GenerateMultisigEventFunc == nil {
		return nil, unset("GenerateMultisigEvent")
	}
	return e.GenerateMultisigEventFunc(aids, threshold, currentKeys, nextKeys, eventType)
}

func (e *Engine) Interact(name string, data []interface{}) (*drivers.DriverInteractResponse, error) {
	if e.InteractFunc == nil {
		return nil, unset("Interact")
	}
	return e.InteractFunc(name, data)
}

func (e *Engine) GetKel(name string) (*drivers.DriverKelResponse, error) {
	if e.GetKelFunc == nil {
		return nil, unset("GetKel")
	}
	return e.GetKelFunc(name)
}

func (e *Engine) ValidateKEL(aid string, events []map[string]interface{}) (*drivers.DriverValidateKELResponse, error) {
	if e.ValidateKELFunc == nil {
		return nil, unset("ValidateKEL")
	}
	return e.ValidateKELFunc(aid, events)
}

func (e *Engine) ValidateKELBytes(in drivers.ValidateKELInput) (*drivers.DriverValidateKELResponse, error) {
	if e.ValidateKELBytesFunc == nil {
		return nil, unset("ValidateKELBytes")
	}
	return e.ValidateKELBytesFunc(in)
}

func (e *Engine) SignPayload(name, dataB64 string) (*drivers.DriverSignResponse, error) {
	if e.SignPayloadFunc == nil {
		return nil, unset("SignPayload")
	}
	return e.SignPayloadFunc(name, dataB64)
}

func (e *Engine) VerifySignature(dataB64, signature, publicKey string) (*drivers.DriverVerifyResponse, error) {
	if e.VerifySignatureFunc == nil {
		return nil, unset("VerifySignature")
	}
	return e.VerifySignatureFunc(dataB64, signature, publicKey)
}

func (e *Engine) CesrEncode(rawSigB64 string) (*drivers.DriverCesrEncodeResponse, error) {
	if e.CesrEncodeFunc == nil {
		return nil, unset("CesrEncode")
	}
	return e.CesrEncodeFunc(rawSigB64)
}

func (e *Engine) FormatCredential(claims map[string]interface{}, schemaSaid, issuerAid string) (*drivers.DriverFormatCredentialResponse, error) {
	if e.FormatCredentialFunc == nil {
		return nil, unset("FormatCredential")
	}
	return e.FormatCredentialFunc(claims, schemaSaid, issuerAid)
}

func (e *Engine) InceptRegistry(name string) (*drivers.DriverRegistryInceptResponse, error) {
	if e.InceptRegistryFunc == nil {
		return nil, unset("InceptRegistry")
	}
	return e.InceptRegistryFunc(name)
}

func (e *Engine) IssueCredential(name string, claims map[string]interface{}, schemaSaid, holderAid string, edges map[string]interface{}) (*drivers.DriverIssueCredentialResponse, error) {
	if e.IssueCredentialFunc == nil {
		return nil, unset("IssueCredential")
	}
	return e.IssueCredentialFunc(name, claims, schemaSaid, holderAid, edges)
}

func (e *Engine) IssueCredentialInRegistry(name string, claims map[string]interface{}, schemaSaid, holderAid string, edges map[string]interface{}, registrySaid string) (*drivers.DriverIssueCredentialResponse, error) {
	if e.IssueCredentialInRegistryFunc == nil {
		return nil, unset("IssueCredentialInRegistry")
	}
	return e.IssueCredentialInRegistryFunc(name, claims, schemaSaid, holderAid, edges, registrySaid)
}

func (e *Engine) RevokeCredential(name, acdcSaid, registrySaid, issSaid string) (*drivers.DriverRevokeCredentialResponse, error) {
	if e.RevokeCredentialFunc == nil {
		return nil, unset("RevokeCredential")
	}
	return e.RevokeCredentialFunc(name, acdcSaid, registrySaid, issSaid)
}

func (e *Engine) VerifyCredential(req *drivers.DriverVerifyCredentialRequest) (*drivers.DriverVerifyCredentialResponse, error) {
	if e.VerifyCredentialFunc == nil {
		return nil, unset("VerifyCredential")
	}
	return e.VerifyCredentialFunc(req)
}

func (e *Engine) PresentCredential(acdcSaid, holderAid, issuerAid, schemaSaid string) (*drivers.DriverPresentCredentialResponse, error) {
	if e.PresentCredentialFunc == nil {
		return nil, unset("PresentCredential")
	}
	return e.PresentCredentialFunc(acdcSaid, holderAid, issuerAid, schemaSaid)
}

func (e *Engine) SubmitReceipt(req *drivers.DriverSubmitReceiptRequest) (*drivers.DriverSubmitReceiptResponse, error) {
	if e.SubmitReceiptFunc == nil {
		return nil, unset("SubmitReceipt")
	}
	return e.SubmitReceiptFunc(req)
}

func (e *Engine) ResolveOobi(url string) (*drivers.DriverResolveOobiResponse, error) {
	if e.ResolveOobiFunc == nil {
		return nil, unset("ResolveOobi")
	}
	return e.ResolveOobiFunc(url)
}

func (e *Engine) EndpointLocation(req *drivers.DriverEndpointLocationRequest) (*drivers.DriverEndpointResponse, error) {
	if e.EndpointLocationFunc == nil {
		return nil, unset("EndpointLocation")
	}
	return e.EndpointLocationFunc(req)
}

func (e *Engine) Start() error {
	if e.StartFunc == nil {
		return nil
	}
	return e.StartFunc()
}

func (e *Engine) Stop() {
	if e.StopFunc != nil {
		e.StopFunc()
	}
}

func (e *Engine) GetStatus() (*drivers.DriverStatus, error) {
	if e.GetStatusFunc == nil {
		return &drivers.DriverStatus{Status: "active", Driver: "driverfake"}, nil
	}
	return e.GetStatusFunc()
}

func (e *Engine) ReloadIdentity(req *drivers.DriverReloadIdentityRequest) (*drivers.DriverReloadIdentityResponse, error) {
	if e.ReloadIdentityFunc == nil {
		return &drivers.DriverReloadIdentityResponse{Status: "ok"}, nil
	}
	return e.ReloadIdentityFunc(req)
}
