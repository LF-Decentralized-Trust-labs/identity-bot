package anchored

// The publisher this build trusts, set at build time:
//
//	go build -ldflags "-X identity-agent-core/measurementlist/anchored.PinnedPublisher=<aid> \
//	  -X identity-agent-core/measurementlist/anchored.PinnedInception=<unpadded base64url of the inception event> \
//	  -X identity-agent-core/measurementlist/anchored.PinnedRegistry=<registry id> \
//	  -X identity-agent-core/measurementlist/anchored.PinnedSchema=<schema SAID>"
//
// Empty by default, so a build that is not given a publisher accepts no list. It
// is deliberately not read from the environment: whoever starts the process is
// not who decides whom the owner trusts. No key is pinned, only the identity.
var (
	PinnedPublisher = ""
	PinnedInception = ""
	PinnedRegistry  = ""
	PinnedSchema    = ""
)

// Pinned returns the publisher compiled into this build, or ErrNoPin.
func Pinned() (Pin, error) {
	return ParsePin(PinnedPublisher, PinnedInception, PinnedRegistry, PinnedSchema)
}
