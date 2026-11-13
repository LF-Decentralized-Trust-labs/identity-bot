package anchored

// The publisher this build trusts, set at build time:
//
//	go build -ldflags "-X identity-agent-core/measurementlist/anchored.PinnedPublisher=<aid> \
//	  -X identity-agent-core/measurementlist/anchored.PinnedInception=<unpadded base64url of the inception event> \
//	  -X identity-agent-core/measurementlist/anchored.PinnedRegistry=<registry id>"
//
// Empty by default, so a build that is not given a publisher accepts no list. It
// is deliberately not read from the environment: whoever starts the process is
// not who decides whom the owner trusts. No key is pinned, only the identity.
//
// The schema is not set here: it is a committed document in this package
// (SchemaDocument), and its SAID is the document's own.
var (
	PinnedPublisher = ""
	PinnedInception = ""
	PinnedRegistry  = ""
)

// Pinned returns the publisher compiled into this build, or ErrNoPin.
func Pinned() (Pin, error) {
	schema, err := SchemaSAID()
	if err != nil {
		return Pin{}, err
	}
	return ParsePin(PinnedPublisher, PinnedInception, PinnedRegistry, schema)
}
