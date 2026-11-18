import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:login_dart/app_checks.dart';
import 'package:login_dart/apple_attest.dart';
import 'package:login_dart/front_end_key.dart';
import 'package:login_dart/installed_app.dart';
import 'package:login_dart/tpm_evidence.dart';

import 'secure_grant_store.dart';

/// The device's secure hardware, reached through the platform's own code (the
/// plugin's android/, darwin/ and windows/ folders). One channel, four calls, the ones
/// `HardwareKeyPlatform` names; the key never crosses it, only its public point,
/// signatures and the platform's evidence, all as bytes.
///
/// No hardware is attached to this repository's tests: they run this class
/// against a fake channel, which holds the Dart half of the contract to what each
/// platform's code returns (see the README for what is untested on a device).
class MethodChannelHardwareKey implements HardwareKeyPlatform {
  static const channelName = 'org.identityagent.login_flutter/hardware_key';
  final MethodChannel _channel;
  final String _platform;

  MethodChannelHardwareKey({MethodChannel? channel, String? platform})
      : _channel = channel ?? const MethodChannel(channelName),
        _platform = platform ?? _platformHere();

  static String _platformHere() {
    switch (defaultTargetPlatform) {
      case TargetPlatform.android:
        return InstalledPlatform.android;
      case TargetPlatform.iOS:
      case TargetPlatform.macOS:
        return InstalledPlatform.apple;
      case TargetPlatform.windows:
        return InstalledPlatform.tpm;
      default:
        throw UnsupportedError(
            'This platform has no secure hardware an app\'s key can be proved in.');
    }
  }

  @override
  String get platform => _platform;

  Future<Uint8List> _bytes(String method, Map<String, Object> args) async {
    final r = await _channel.invokeMethod<Uint8List>(method, args);
    if (r == null) {
      throw PlatformException(
          code: 'no_answer',
          message: 'the device\'s hardware gave no answer to $method');
    }
    return r;
  }

  @override
  bool get callProofIsAssertion => _platform == InstalledPlatform.apple;

  @override
  Future<Uint8List?> publicPoint(String label) =>
      _channel.invokeMethod<Uint8List>('publicPoint', {'label': label});

  @override
  Future<Uint8List> signCall(String label, Uint8List message) =>
      _bytes('signCall', {'label': label, 'message': message});

  @override
  Future<({Uint8List point, Uint8List evidence})> attestNewKey(
      String label, Uint8List challenge,
      {CredentialExchange? exchange}) async {
    if (_platform == InstalledPlatform.tpm) return _attestTpm(label, challenge, exchange);
    if (_platform == InstalledPlatform.apple) {
      // The device gives an App Attest key only as an identifier, so its public point is
      // read from the attestation object, and kept for the next run.
      final evidence = await _bytes(
          'attestNewKey', {'label': label, 'challenge': challenge});
      final point = appleAttestedPoint(evidence);
      await _channel
          .invokeMethod<void>('keepPoint', {'label': label, 'point': point});
      return (point: point, evidence: evidence);
    }
    final r = await _channel.invokeMapMethod<String, Object?>(
        'attestNewKey', {'label': label, 'challenge': challenge});
    final point = r?['point'], evidence = r?['evidence'];
    if (point is! Uint8List || evidence is! Uint8List) {
      throw PlatformException(
          code: 'no_answer',
          message: 'the device\'s hardware gave no key and evidence');
    }
    return (point: point, evidence: evidence);
  }

  @override
  Future<Uint8List> signStatement(String label, Uint8List statementDigest) =>
      _bytes('signStatement', {'label': label, 'digest': statementDigest});

  /// A TPM's evidence is made in two calls with the Identity Agent between them:
  /// `tpmEnrol` makes the attestation key and reads the endorsement key and its
  /// certificate; the Identity Agent's credential for them comes back through
  /// [exchange]; `tpmAttest` makes the app key, opens the credential in the TPM
  /// and has the attestation key certify the key for [challenge].
  Future<({Uint8List point, Uint8List evidence})> _attestTpm(
      String label, Uint8List challenge, CredentialExchange? exchange) async {
    if (exchange == null) {
      throw PlatformException(
          code: 'no_credential_exchange',
          message: 'a TPM\'s key is proved through the Identity Agent\'s credential, '
              'and nothing was given to ask for it');
    }
    final e = await _channel.invokeMapMethod<String, Object?>(
        'tpmEnrol', {'label': label});
    Uint8List need(Map<String, Object?>? m, String k) {
      final v = m?[k];
      if (v is! Uint8List || v.isEmpty) {
        throw PlatformException(
            code: 'no_answer', message: 'the device\'s TPM gave no $k');
      }
      return v;
    }

    final chain = e?['ek_chain'];
    final enrolment = TpmEnrolment(
        ekPublic: need(e, 'ek_public'),
        ekCert: need(e, 'ek_cert'),
        akPublic: need(e, 'ak_public'),
        ekChain: [
          if (chain is List)
            for (final c in chain)
              if (c is Uint8List) c
        ]);
    final credential = await exchange(enrolment);
    final r = await _channel.invokeMapMethod<String, Object?>('tpmAttest', {
      'label': label,
      'challenge': challenge,
      'credential_blob': credential.credentialBlob,
      'secret': credential.secret,
    });
    final point = need(r, 'point');
    final attested = TpmAttested(
        keyPublic: need(r, 'key_public'),
        certifyInfo: need(r, 'certify_info'),
        certifySignature: need(r, 'certify_signature'),
        credentialSecret: need(r, 'credential_secret'));
    return (point: point, evidence: tpmEvidence(enrolment, attested));
  }
}

/// The installed front end's key for [link] (ADR-072 Amendment 17): made in this
/// device's secure hardware where the app's owner accepts it, and otherwise, where
/// the owner does not require a hardware key, held in software in the platform's
/// secure storage. A device with no secure hardware an app's key can be proved in
/// (Linux, for one) has only the second. The Identity Agent decides which it takes.
Future<InstalledFrontEndKey> openInstalledFrontEndKey(AppLink link,
    {HardwareKeyPlatform? hardware,
    FlutterSecureStorage? storage,
    String label = 'identity-agent.app-key'}) {
  HardwareKeyPlatform? here = hardware;
  if (here == null) {
    try {
      here = MethodChannelHardwareKey();
    } on UnsupportedError {
      here = null;
    }
  }
  return InstalledFrontEndKey.open(
      hardware: here,
      label: '$label:${link.aid}',
      keyStore: SecureGrantStore(keySlot(link.aid, link.rid, link.api),
          storage: storage));
}
