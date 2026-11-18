#include "include/login_flutter/login_flutter_plugin_c_api.h"

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>

#include <memory>
#include <string>

#include "tpm_key.h"

// The channel `MethodChannelHardwareKey` (lib/src/hardware_key.dart) speaks, on Windows.
// NOT COMPILED OR RUN: see README, "What runs where, and what has been tried".

namespace {

using flutter::EncodableList;
using flutter::EncodableMap;
using flutter::EncodableValue;
using Result = flutter::MethodResult<EncodableValue>;

const std::vector<unsigned char>* Bytes(const EncodableMap& m, const char* k) {
  auto it = m.find(EncodableValue(k));
  return it == m.end() ? nullptr : std::get_if<std::vector<unsigned char>>(&it->second);
}

void Answer(Result& result, std::optional<tpm_key::Bytes> v, const tpm_key::Failure& why) {
  if (v) result.Success(EncodableValue(*v));
  else if (!why.code.empty()) result.Error(why.code, why.message);
  else result.Success();  // no key yet
}

EncodableValue Value(const tpm_key::Bytes& b) { return EncodableValue(std::vector<unsigned char>(b.begin(), b.end())); }

void Fail(Result& result, const tpm_key::Failure& why) { result.Error(why.code.empty() ? "tpm" : why.code, why.message); }

void Handle(const flutter::MethodCall<EncodableValue>& call, std::unique_ptr<Result> result) {
  const auto* args = std::get_if<EncodableMap>(call.arguments());
  const std::string* label = nullptr;
  if (args) {
    auto it = args->find(EncodableValue("label"));
    if (it != args->end()) label = std::get_if<std::string>(&it->second);
  }
  if (!label) return result->Error("bad_args", "no label");
  tpm_key::Failure why;
  const auto& m = call.method_name();
  if (m == "publicPoint") {
    Answer(*result, tpm_key::PublicPoint(*label, &why), why);
  } else if (m == "keepPoint") {
    result->Success();  // the key's blob holds its point; nothing to keep
  } else if (m == "tpmEnrol") {
    // Step one of a TPM's evidence: the attestation key and the endorsement key and
    // its certificate, which go to the Identity Agent for a credential (login_flutter's
    // Dart half sends them and calls tpmAttest with what comes back).
    auto e = tpm_key::Enrol(*label, &why);
    if (!e) return Fail(*result, why);
    EncodableList chain;
    for (const auto& c : e->ek_chain) chain.push_back(Value(c));
    result->Success(EncodableValue(EncodableMap{{EncodableValue("ek_public"), Value(e->ek_public)},
                                                {EncodableValue("ek_cert"), Value(e->ek_cert)},
                                                {EncodableValue("ek_chain"), EncodableValue(chain)},
                                                {EncodableValue("ak_public"), Value(e->ak_public)}}));
  } else if (m == "tpmAttest") {
    const auto* challenge = args ? Bytes(*args, "challenge") : nullptr;
    const auto* credential = args ? Bytes(*args, "credential_blob") : nullptr;
    const auto* secret = args ? Bytes(*args, "secret") : nullptr;
    if (!challenge || !credential || !secret) return result->Error("bad_args", "no challenge, credential or secret");
    auto a = tpm_key::Attest(*label, *challenge, *credential, *secret, &why);
    if (!a) return Fail(*result, why);
    result->Success(EncodableValue(EncodableMap{{EncodableValue("point"), Value(a->point)},
                                                {EncodableValue("key_public"), Value(a->key_public)},
                                                {EncodableValue("certify_info"), Value(a->certify_info)},
                                                {EncodableValue("certify_signature"), Value(a->certify_signature)},
                                                {EncodableValue("credential_secret"), Value(a->credential_secret)}}));
  } else if (m == "signCall") {
    const auto* b = args ? Bytes(*args, "message") : nullptr;
    if (!b) return result->Error("bad_args", "no message");
    Answer(*result, tpm_key::SignCall(*label, *b, &why), why);
  } else if (m == "signStatement") {
    const auto* b = args ? Bytes(*args, "digest") : nullptr;
    if (!b || b->size() != 32) return result->Error("bad_args", "no digest");
    Answer(*result, tpm_key::SignDigest(*label, *b, &why), why);
  } else {
    result->NotImplemented();
  }
}

class LoginFlutterPlugin : public flutter::Plugin {
 public:
  static void Register(flutter::PluginRegistrarWindows* registrar) {
    auto channel = std::make_unique<flutter::MethodChannel<EncodableValue>>(
        registrar->messenger(), "org.identityagent.login_flutter/hardware_key",
        &flutter::StandardMethodCodec::GetInstance());
    channel->SetMethodCallHandler([](const auto& call, auto result) { Handle(call, std::move(result)); });
    registrar->AddPlugin(std::make_unique<LoginFlutterPlugin>(std::move(channel)));
  }
  explicit LoginFlutterPlugin(std::unique_ptr<flutter::MethodChannel<EncodableValue>> c) : channel_(std::move(c)) {}

 private:
  std::unique_ptr<flutter::MethodChannel<EncodableValue>> channel_;
};

}  // namespace

void LoginFlutterPluginCApiRegisterWithRegistrar(FlutterDesktopPluginRegistrarRef registrar) {
  LoginFlutterPlugin::Register(
      flutter::PluginRegistrarManager::GetInstance()->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
