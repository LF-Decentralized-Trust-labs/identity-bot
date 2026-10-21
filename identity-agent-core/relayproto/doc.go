// Package relayproto is the relay protocol both ends share: how an Identity
// Agent that only dials out is admitted by a relay, and how the relay carries
// HTTP to it. ADR-048 is the specification; this package is the one
// implementation of it, imported by the Identity Agent and by any relay server,
// so the two ends cannot drift apart.
//
// The shape, in one paragraph. The Identity Agent opens one websocket to the
// relay over TLS. The relay sends a challenge, and the agent answers with a
// statement signed by its enrolment key that names the relay, the challenge and
// this TLS connection, plus the key event log that binds that key to its
// identifier. Once admitted, the websocket carries a yamux session in which only
// the relay opens streams. Each inbound request gets its own stream, which
// starts with a preamble the relay writes (which allocation, which mode, which
// host) and then carries ordinary HTTP. The agent serves those streams with an
// ordinary http.Server, so upgrades, streaming, query strings and headers are
// HTTP's own. An admission is a lease: before it runs out, the relay challenges
// again over a control stream, and a session that cannot answer is closed.
//
// What each side calls:
//
//   - the relay: [Accept] on its websocket endpoint, then [Registry] to find a
//     session by identifier and [Session.Forward] to carry a request to it;
//   - the Identity Agent: [Dial], then [AgentSession.Serve] with its handler,
//     reading [PreambleFrom] in that handler to learn which allocation a request
//     arrived on.
package relayproto
