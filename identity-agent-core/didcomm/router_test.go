package didcomm

import "testing"

// Every type that crosses the envelope layer has to be registered here, because
// an unregistered one is rejected on unpack — before any handler that would
// otherwise check it. A type used by working code and absent from this map is
// therefore not a naming oversight; it is a transport that cannot carry
// anything, which is what this catches.
func TestEveryTypeTheCodeSendsIsRegistered(t *testing.T) {
	for _, typ := range []string{
		TypeCredentialOffer, TypeCredentialRequest, TypeCredentialIssuance,
		TypeKeriEvent, TypeContactRequest, TypeDirectMessage, TypeAck,
		TypeNotification, TypeAgentMessage, TypeAgentTask, TypeAgentResult,
		TypeSealedRequest, TypeSealedResponse,
	} {
		if !KnownType(typ) {
			t.Errorf("%q is used by the code but unregistered, so anything sent "+
				"with it is rejected on unpack", typ)
		}
	}
}
