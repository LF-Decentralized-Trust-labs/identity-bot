package keriengine

import (
	"fmt"

	"identity-agent-core/drivers"
)

// Discovery and presentation: the three operations this engine does not answer.
//
// They are not KERI event construction. Resolving an OOBI means fetching a
// document over the network and deciding whether to trust what comes back;
// publishing an endpoint means producing a signed reply message; presenting a
// credential means building a disclosure for a particular verifier. The KERI
// library underneath this engine builds and verifies events, and none of these
// three is one.
//
// They refuse rather than approximate. A resolver that returned nothing would
// look to a caller exactly like an identity with no endpoints, and a
// presentation built wrongly would be rejected by the verifier it was built
// for, with the failure surfacing far from its cause.
//
// So an engine that cannot do these says so, and a deployment that needs them
// keeps an implementation that can — which is what the interface these sit
// behind is for.

// SupportsDiscovery reports whether this engine can resolve OOBIs, publish
// endpoints and build presentations.
//
// A caller holding the interface can ask before routing work here, rather than
// discovering the answer from a failed call.
func (e *Engine) SupportsDiscovery() bool { return false }

func (e *Engine) ResolveOobi(url string) (*drivers.DriverResolveOobiResponse, error) {
	return nil, fmt.Errorf("this engine does not resolve OOBIs. Resolving %q means fetching a "+
		"key log over the network and deciding whether to trust it, which is a different job "+
		"from building and verifying events. Route this to an implementation that performs "+
		"discovery", url)
}

func (e *Engine) EndpointLocation(req *drivers.DriverEndpointLocationRequest) (*drivers.DriverEndpointResponse, error) {
	return nil, fmt.Errorf("this engine does not publish endpoint locations. Announcing where an " +
		"identity can be reached means producing a signed reply message, and this engine holds " +
		"no keys to sign one with. Route this to an implementation that performs discovery")
}

func (e *Engine) PresentCredential(acdcSaid, holderAid, issuerAid, schemaSaid string) (*drivers.DriverPresentCredentialResponse, error) {
	return nil, fmt.Errorf("this engine does not build credential presentations. Presenting %s "+
		"means producing a disclosure for a particular verifier and signing it as the holder, "+
		"and this engine holds no keys. Route this to an implementation that performs "+
		"presentation", acdcSaid)
}
