#pragma once
// The TPM 2.0 commands the Windows hardware key needs, written against the
// TCG library specification (Part 3 commands, Part 2 structures), with no
// Windows header: the transport is whatever carries a command to a TPM and brings
// its response back (on Windows, TBS; in test/, a software TPM over a socket).
// That is what makes this code testable off Windows: test/ runs it against the
// reference TPM implementation and checks what it makes with the Identity Agent's
// own code (identity-agent-core/secureenclave).
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace tpm2 {

using Bytes = std::vector<uint8_t>;
// Sends one command, fills the response. False when the TPM could not be reached.
using Transport = std::function<bool(const Bytes& command, Bytes* response)>;

struct Failure {
  std::string code;  // short, for the channel's error code
  std::string message;
  uint32_t tpm_rc = 0;
};

Bytes Sha256(const Bytes& data);

struct Created {  // a key made under a parent: its blob and public area
  Bytes private_blob;  // TPM2B_PRIVATE, usable only in this TPM under this parent
  Bytes public_area;   // TPM2B_PUBLIC
};

class Device {
 public:
  explicit Device(Transport t) : t_(std::move(t)) {}

  // The storage key everything is made under: an ECC P-256 primary of the owner
  // hierarchy from one fixed template, so the same key is made again every time.
  std::optional<uint32_t> Srk(Failure* why);
  // The endorsement key, from the standard TCG RSA 2048 template (the one the
  // manufacturer's EK certificate certifies). Its TPM2B_PUBLIC is in *pub.
  std::optional<uint32_t> Ek(Bytes* pub, Failure* why);
  // A restricted P-256 signing key (an attestation key) / an unrestricted one
  // (the app's key), made under parent.
  std::optional<Created> CreateAk(uint32_t parent, Failure* why);
  std::optional<Created> CreateAppKey(uint32_t parent, Failure* why);
  std::optional<uint32_t> Load(uint32_t parent, const Created& key, Failure* why);
  void Flush(uint32_t handle);

  // TPM2_ActivateCredential for ak, with the EK's policy session (PolicySecret on
  // the endorsement hierarchy). credential and secret are TPM2B_ID_OBJECT and
  // TPM2B_ENCRYPTED_SECRET as the Identity Agent made them. Returns what was released.
  std::optional<Bytes> ActivateCredential(uint32_t ak, uint32_t ek, const Bytes& credential, const Bytes& secret, Failure* why);

  // TPM2_Certify of object by signer: the TPMS_ATTEST (no size prefix) and the TPMT_SIGNATURE.
  struct Certified { Bytes attest, signature; };
  std::optional<Certified> Certify(uint32_t object, uint32_t signer, const Bytes& qualifying, Failure* why);

  // ECDSA P-256 over a 32-byte digest, as the 64 bytes r then s.
  std::optional<Bytes> Sign(uint32_t key, const Bytes& digest32, Failure* why);

  // The EK certificate the manufacturer wrote into the TPM (NV index
  // 0x01C00002), or nullopt when there is none there.
  std::optional<Bytes> ReadEkCertificate(Failure* why);

 private:
  struct Reply { uint32_t rc = 0; Bytes body; };  // body: after the 10-byte header
  bool Run(uint16_t tag, uint32_t code, const Bytes& handles, const Bytes& auth, const Bytes& params, Reply* out, Failure* why);
  Transport t_;
};

// The public point of a TPM2B_PUBLIC for an ECC P-256 key: 0x04 || x || y.
std::optional<Bytes> EccPoint(const Bytes& tpm2b_public);
// The 64-byte r||s inside a TPMT_SIGNATURE (ECDSA), as ASN.1 DER.
Bytes RawToDer(const Bytes& rs64);
// The qualifying data the Identity Agent expects TPM2_Certify to be given for a challenge
// (secureenclave.TPMCertifyExtraData).
Bytes CertifyExtraData(const Bytes& challenge);

// What `MakeEnrolment` and `Attest` keep between the two channel calls and across runs.
struct BlobStore {
  virtual ~BlobStore() = default;
  virtual bool Put(const std::string& name, const Bytes& v) = 0;
  virtual std::optional<Bytes> Get(const std::string& name) = 0;
};

struct Enrolment { Bytes ek_public, ek_cert, ak_public; std::vector<Bytes> ek_chain; };
struct Attested { Bytes point, key_public, certify_info, certify_signature, credential_secret; };

// The front end's half of the credential exchange (ADR-072 Amendment 3), in two
// steps with the Identity Agent between them. ek_cert reads the EK certificate
// (the Windows layer may know a better way than the TPM's own NV memory).
std::optional<Enrolment> MakeEnrolment(Device& d, BlobStore& store, const std::string& label,
                                       const std::function<std::optional<Bytes>()>& ek_cert, Failure* why);
std::optional<Attested> Attest(Device& d, BlobStore& store, const std::string& label, const Bytes& challenge,
                               const Bytes& credential, const Bytes& secret, Failure* why);
std::optional<Bytes> PublicPointOf(BlobStore& store, const std::string& label);
// ECDSA over a 32-byte digest by the app key, as ASN.1 DER.
std::optional<Bytes> SignDigest(Device& d, BlobStore& store, const std::string& label, const Bytes& digest, Failure* why);

}  // namespace tpm2
