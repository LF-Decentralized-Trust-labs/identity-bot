#pragma once
#include <optional>
#include <string>
#include <vector>

#include "tpm2.h"

// The Windows side of the hardware key: a P-256 signing key made and held in the
// computer's TPM, and the evidence that it is (ADR-072 Amendment 3, the TPM row).
//
// The TPM is reached through TBS (the TPM Base Services), which carries TCG commands
// from a program to the TPM; the commands are tpm2.cpp's, which is held against a
// software TPM and the Identity Agent's own verifier (test/). The key's blob (its
// private part only the TPM can open) is kept in a file under the user's own
// profile, encrypted to the user with DPAPI. What a TPM does not say is which
// program holds its key, so this proves a key is in a TPM and not that it is this
// app's: the owner must have accepted that (`tpm_keys`).
//
// NOT RUN ON WINDOWS: see README, "What runs where, and what has been tried".
namespace tpm_key {

using Bytes = tpm2::Bytes;
using Failure = tpm2::Failure;

// The uncompressed P-256 point (65 bytes, 0x04 first) of the key named by label, if there is one.
std::optional<Bytes> PublicPoint(const std::string& label, Failure* why);

// Step one of the evidence: the attestation key and the endorsement key's public
// area and certificate, to send to the Identity Agent for a credential.
std::optional<tpm2::Enrolment> Enrol(const std::string& label, Failure* why);

// Step two: opens the credential in the TPM, makes the key and has the attestation key certify it for challenge.
std::optional<tpm2::Attested> Attest(const std::string& label, const Bytes& challenge, const Bytes& credential,
                                     const Bytes& secret, Failure* why);

// ECDSA P-256 over SHA-256 of message, as ASN.1 DER.
std::optional<Bytes> SignCall(const std::string& label, const Bytes& message, Failure* why);

// ECDSA P-256 over digest (the SHA-256 of the sign-in statement) as it is, as ASN.1 DER.
std::optional<Bytes> SignDigest(const std::string& label, const Bytes& digest, Failure* why);

}  // namespace tpm_key
