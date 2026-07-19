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
    if (Platform.isIOS) {
      return EnclaveStatusResponse(
        hardwareBacked: true,
        backingType: 'secure_enclave',
        backingLabel: 'Apple Secure Enclave',
      );
    }

    if (Platform.isAndroid) {
      // Android StrongBox (hardware) vs TEE (hardware) vs software.
      // flutter_secure_storage uses the best available automatically.
      // We report hardware-backed since modern Android (API 23+) has TEE,
      // and we can't query StrongBox presence without platform channels.
      return EnclaveStatusResponse(
        hardwareBacked: true,
        backingType: 'android_keystore',
        backingLabel: 'Android Keystore (hardware)',
      );
    }

    // Desktop — ask the Go backend
    if (_coreService != null) {
      try {
        return await _coreService.getEnclaveStatus();
      } catch (_) {
        // Fallback if backend unreachable
      }
    }

    return EnclaveStatusResponse(
      hardwareBacked: false,
      backingType: 'software',
      backingLabel: 'Software (unknown)',
    );
  }
}
