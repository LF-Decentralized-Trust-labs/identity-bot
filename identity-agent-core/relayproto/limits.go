package relayproto

import "time"

// The numbers ADR-048 fixes. They are part of the protocol, not tuning: a
// relay and an Identity Agent that disagree about them disagree about what is
// allowed.
const (
	// ProtocolVersion names this protocol in every challenge and statement.
	ProtocolVersion = "iarelay/2"
	// Subprotocol is the websocket subprotocol both ends negotiate.
	Subprotocol = "iarelay.v2"

	// ExporterLabel is the RFC 9266 channel-binding label. The value it yields
	// is unique to one TLS connection, so a statement that names it is useless
	// on any other.
	ExporterLabel = "EXPORTER-Channel-Binding"
	// ExporterLength is the size of the exporter value, in bytes.
	ExporterLength = 32

	// NonceBytes is the size of a relay's challenge nonce.
	NonceBytes = 32
	// ClockSkew is how far a statement's time may be from the relay's.
	ClockSkew = 2 * time.Minute

	// MaxKELBytes and MaxKELEvents bound the key event log an admission may
	// carry, so admitting somebody cannot cost unbounded work.
	MaxKELBytes  = 64 << 10
	MaxKELEvents = 256

	// LeaseLifetime is how long one admission lasts. The relay challenges again
	// RenewBefore its end; a session that does not answer is closed when it
	// ends.
	LeaseLifetime = 10 * time.Minute
	RenewBefore   = 1 * time.Minute
	// HandshakeTimeout bounds each admission exchange.
	HandshakeTimeout = 30 * time.Second

	// MaxStreamsPerSession is how many requests may be in flight to one
	// Identity Agent at once. Both ends enforce it.
	MaxStreamsPerSession = 256
	// StreamWindowBytes is how many bytes may be in flight on one stream
	// before the receiver reads them.
	StreamWindowBytes = 256 << 10
	// MaxPreambleBytes bounds a stream preamble.
	MaxPreambleBytes = 1 << 10
	// MaxFrameBytes bounds one websocket message carrying the session.
	MaxFrameBytes = 1 << 20

	// LargeBodyBytes is the size above which a request body crosses the relay
	// only after the Identity Agent has accepted the request on its headers
	// (Expect: 100-continue). A body of unknown length counts as large.
	LargeBodyBytes = 1 << 20
	// MaxPrivateBodyBytes bounds a request body on a private allocation, which
	// carries identity artifacts and messages and nothing larger.
	MaxPrivateBodyBytes = 1 << 20

	// Requests per minute an allocation may receive, by mode. A public
	// address serves a user interface; a private one answers one counterparty.
	PublicRequestsPerMinute  = 1200
	PrivateRequestsPerMinute = 120
)
