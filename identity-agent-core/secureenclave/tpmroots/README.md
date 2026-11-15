# Pinned TPM manufacturer roots

`tpmroots/*.pem` are the trust anchors an endorsement-key certificate must chain to
(`tpm_key_certify.go`, `verifyEKCertificate`), and `../tpmintermediates/*.pem` the issuers a
chain may pass through, so a front end need not send them. They are Microsoft's trusted TPM
root certificate list, the one Windows device attestation uses; Rob decided on 2026-11-14 to
trust it. `SOURCE.txt` records the package URL, its SHA-256 and the date it was fetched,
and lists every certificate with its maker, and any it could not pin (Go refuses a malformed serial number: 6 of STMicroelectronics' issuers are among them, so chains through those fail until they are supplied another way).

To update: `secureenclave/tpmroots/update.sh` (from `identity-agent-core`), then read the diff
and `SOURCE.txt` before committing. Nothing else changes.

What this trusts: a certificate chain to one of these roots, and a leaf marked as a TCG
endorsement key certificate. Microsoft's list also holds certificates for its own
virtual and cloud TPMs, so an endorsement key of that kind chains too; the owner's
`tpm_keys` setting is what says a TPM key is accepted at all.
