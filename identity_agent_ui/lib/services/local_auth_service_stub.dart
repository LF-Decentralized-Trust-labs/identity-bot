/// Stub implementation for web builds — local_auth is not available on web.
enum BiometricMethod { fingerprint, face, none }

enum BiometricAvailability { available, availableNotEnrolled, unavailable }

class LocalAuthService {
  static Future<bool> isSupported() async => false;

  static Future<BiometricAvailability> fingerprintAvailability() async =>
      BiometricAvailability.unavailable;

  static Future<BiometricAvailability> faceAvailability() async =>
      BiometricAvailability.unavailable;

  static Future<bool> authenticate({required String reason}) async => false;
}
