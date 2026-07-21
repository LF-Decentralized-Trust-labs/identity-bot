import 'package:local_auth/local_auth.dart';

enum BiometricMethod { fingerprint, face, none }

enum BiometricAvailability { available, availableNotEnrolled, unavailable }

class LocalAuthService {
  static final _auth = LocalAuthentication();

  /// Whether the device supports any form of biometric or device authentication.
  static Future<bool> isSupported() async {
    return await _auth.isDeviceSupported();
  }

  static Future<BiometricAvailability> fingerprintAvailability() async {
    return _availability(BiometricType.fingerprint);
  }

  static Future<BiometricAvailability> faceAvailability() async {
    return _availability(BiometricType.face);
  }

  static Future<BiometricAvailability> _availability(BiometricType type) async {
    try {
      final canCheck = await _auth.canCheckBiometrics;
      if (!canCheck) return BiometricAvailability.unavailable;

      final enrolled = await _auth.getAvailableBiometrics();
      if (enrolled.contains(type)) return BiometricAvailability.available;

      // Device supports biometrics in general — this type just isn't enrolled
      final isSupported = await _auth.isDeviceSupported();
      return isSupported
          ? BiometricAvailability.availableNotEnrolled
          : BiometricAvailability.unavailable;
    } catch (_) {
      return BiometricAvailability.unavailable;
    }
  }

  /// Prompts the user to authenticate. Returns true on success.
  ///
  /// On iOS/Android: shows Face ID / fingerprint prompt.
  /// On Windows: shows Windows Hello dialog.
  /// On macOS: shows Touch ID / password prompt.
  static Future<bool> authenticate({required String reason}) async {
    try {
      return await _auth.authenticate(
        localizedReason: reason,
        options: const AuthenticationOptions(
          biometricOnly: false, // allow PIN/password fallback on device
          stickyAuth: true,     // don't cancel if user leaves app briefly
        ),
      );
    } catch (_) {
      return false;
    }
  }
}
