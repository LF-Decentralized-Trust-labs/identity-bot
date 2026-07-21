import 'dart:io';
import 'core_service.dart';

export 'core_service.dart' show EnclaveStatusResponse;

/// Detects hardware security backing on this device.
///
/// On mobile (iOS/Android) we can answer locally from the platform.
/// On desktop the Go backend does a platform-specific probe and we call
/// GET /api/security/enclave.
class EnclaveService {
  final CoreService? _coreService;

  EnclaveService({CoreService? coreService}) : _coreService = coreService;

  Future<EnclaveStatusResponse> detect() async {
    // Prefer the backend's real probe on EVERY platform — it computes the actual
    // device-trust verdict (trustAllowed) from the attestation chain. The local
    // platform heuristics below are only a fallback when no backend is reachable,
    // and they never assert trust (trustAllowed stays null) so a fail-closed
    // caller won't be fooled into proceeding on an unverified device.
    if (_coreService != null) {
      try {
        return await _coreService.getEnclaveStatus();
      } catch (_) {
        // Backend unreachable — fall through to the local platform heuristic.
      }
    }

    if (Platform.isIOS) {
      return EnclaveStatusResponse(
        hardwareBacked: true,
        backingType: 'secure_enclave',
        backingLabel: 'Apple Secure Enclave',
      );
    }
    if (Platform.isAndroid) {
      // Modern Android (API 23+) has a TEE; flutter_secure_storage uses the best
      // available. We can't query StrongBox without a platform channel, so this
      // is a heuristic, not a verified verdict — hence no trustAllowed.
      return EnclaveStatusResponse(
        hardwareBacked: true,
        backingType: 'android_keystore',
        backingLabel: 'Android Keystore (hardware)',
      );
    }
    return EnclaveStatusResponse(
      hardwareBacked: false,
      backingType: 'software',
      backingLabel: 'Software (unknown)',
    );
  }
}
