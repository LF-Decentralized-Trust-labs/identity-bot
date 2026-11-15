# Pinned TPM manufacturer roots

`*.pem` files here are the certificates an endorsement-key certificate must chain
to (`tpm_key_certify.go`, `verifyEKCertificate`). **None is pinned yet, so no
TPM key can be proved and Windows installed apps sign in as `browser`.** Pinning is
a decision about whom the Identity Agent trusts to say "this is a real TPM"; it is
made by adding files here, and nothing else changes.

To make the set from Microsoft's published package, which gathers each maker's
roots under `<maker>/RootCA` (and its issuers under `<maker>/IntermediateCA`):

    go run ./tools/tpmroots -cab TrustedTpm.cab-extracted-dir -out tpmroots

The tool writes one PEM per root, named by the SHA-256 of its DER, and a
`SOURCE.txt` with the package's URL, its SHA-256 and the date it was fetched,
so what is pinned can be traced and replaced.
