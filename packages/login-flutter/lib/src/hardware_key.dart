import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:login_dart/apple_attest.dart';
import 'package:login_dart/front_end_key.dart';
import 'package:login_dart/installed_app.dart';

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
      String label, Uint8List challenge) async {
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
}
