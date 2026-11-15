#include "include/login_flutter/login_flutter_plugin_c_api.h"

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>

#include <memory>
#include <string>

#include "tpm_key.h"

// The channel `MethodChannelHardwareKey` (lib/src/hardware_key.dart) speaks, on Windows.
// NOT COMPILED OR RUN: see tpm_key.cpp.

namespace {

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
    result->Success();  // the TPM can give the point again; nothing to keep
  } else if (m == "attestNewKey") {
    // A new key is made so that the sign-in names a key made for this ask, but the TPM's
    // evidence for it cannot be made yet: the Identity Agent's side of the credential
    // exchange is not built and no TPM manufacturer root is pinned (tpm_key_certify.go).
    // Refusing here says so, rather than handing over evidence that would not be accepted.
    result->Error("tpm_evidence_unavailable",
                  "A Windows TPM key cannot be proved to the Identity Agent yet: it has not "
                  "built its half of the TPM credential exchange or pinned a TPM maker's root.");
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
