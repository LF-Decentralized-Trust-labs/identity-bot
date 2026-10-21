# Signing vectors

The form every service-provider request is signed over is set by ADR-049. Its
vectors live with the code that produces them, in
`identity-agent-core/relayproto/signing-vectors.json`, so the Go module ships
them and other implementations read the same file.
