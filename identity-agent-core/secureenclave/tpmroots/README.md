# Pinned TPM manufacturer roots

`tpmroots/*.pem` are the trust anchors an endorsement-key certificate must chain to
(`tpm_key_certify.go`, `verifyEKCertificate`), and `../tpmintermediates/*.pem` (and `../tpmlenient/*.pem`, below) the issuers a
chain must pass through (the leaf's direct issuer must be one of them, or a pinned root with none
beneath it), so a front end need not send them. They come from Microsoft's trusted TPM root
certificate list, the one Windows device attestation uses, and are trusted for **physical TPM chips
only** (ADR-072 Amendment 10). They are Microsoft's published TPM certificates, redistributed unmodified,
and are not covered by this repository's licence. `SOURCE.txt` records the package URL, its SHA-256 and the date
it was fetched, and lists every certificate with its maker and class.

**Classes.** `tools/tpmroots` marks each certificate *physical*, *virtual* or *unclassified* (the
evidence for each is at the top of `SOURCE.txt`). Only physical ones are pinned in `tpmroots` and
`tpmintermediates`. Microsoft's own TPM issuers (`MSFT-KEYID-…`: the software TPM of Hyper-V and Azure)
are written to `../tpmvirtual`, which is never trusted and only lets a chain through one be refused by
name. A certificate that cannot be classified is written nowhere. The package does not itself name a
certificate as virtual: that reading rests on the vendor id and on Microsoft's own statements, and a
virtual TPM that chains through an issuer this tool took for physical would be accepted, so any
reclassification is a reviewed change to `classify`.

**Issuers Go's X.509 reader refuses.** Six STMicroelectronics issuers encode their serial number with
redundant leading zero bytes, which DER forbids and `crypto/x509` rejects ("malformed serial number"), and
the chips' endorsement key certificates are issued under them. They are pinned by the SHA-256 of their bytes
in `../tpmlenient` (physical only, like the rest) and read by `identity-agent-core/tpmcert`, which accepts that
one irregularity and nothing else. A chain through one is checked directly (`lenientIssuer` in
`tpm_lenient.go`): the endorsement key certificate names the issuer, the issuer's key made its signature,
the issuer is a CA, and a pinned root signed the issuer; all are valid now. Roots are never read this way.
A Qualcomm issuer, `qwes_prod_ek_provisioning_intermediate_glymur_mahua_kalombo.crt`, was skipped for a
different reason: its PEM lines end in a bare carriage return. It is ordinary DER and sits in
`../tpmintermediates` with the others. Only a file that is no certificate (`AMD/IntermediateCA/readme.txt`)
is still skipped, and `SOURCE.txt` says so.

To update: `secureenclave/tpmroots/update.sh` (needs `curl`, `cabextract`, `osslsigncode`, Go; works on
macOS, Linux and Windows under Git Bash). It checks Microsoft's Authenticode signature on the package
against Microsoft Root Certificate Authority 2011 (`tools/tpmroots/microsoft-root-2011.pem`), prints the
package's SHA-256 and stops; run it again with that hash to write the files. Read the diff and
`SOURCE.txt` before committing. Nothing else changes.

What this trusts: a certificate chain to one of these roots through a pinned physical issuer, and a leaf
marked as a TCG endorsement key certificate. The proof records the issuer and its class
(`ek_issuer`, `ek_class`). The owner's `tpm_keys` setting is what says a TPM key is accepted at all.
