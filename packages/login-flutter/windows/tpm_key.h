#pragma once
#include <optional>
#include <string>
#include <vector>

// The Windows side of the hardware key: a P-256 signing key in the computer's TPM, through
// CNG's Microsoft Platform Crypto Provider. The key never leaves it; only its public point
// and signatures do.
namespace tpm_key {

using Bytes = std::vector<unsigned char>;

struct Failure {
  std::string code;
  std::string message;
};

// The uncompressed P-256 point (65 bytes, 0x04 first) of the key named by label, if there is one.
std::optional<Bytes> PublicPoint(const std::string& label, Failure* why);

// Makes a new non-exportable signing key under label, replacing any, and gives its point.
std::optional<Bytes> CreateKey(const std::string& label, Failure* why);

// ECDSA P-256 over SHA-256 of message, as ASN.1 DER.
std::optional<Bytes> SignCall(const std::string& label, const Bytes& message, Failure* why);

// ECDSA P-256 over digest (the SHA-256 of the sign-in statement) as it is, as ASN.1 DER.
std::optional<Bytes> SignDigest(const std::string& label, const Bytes& digest, Failure* why);

}  // namespace tpm_key
