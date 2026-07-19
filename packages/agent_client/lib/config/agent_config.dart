import 'package:flutter/foundation.dart' show kIsWeb;
import 'platform_helper_stub.dart'
    if (dart.library.io) 'platform_helper_io.dart';

class AgentConfig {
  static const int defaultDesktopPort = 5050;

  /// The actual port the backend is running on (may differ from default
  /// if port 5050 was occupied and the backend auto-selected a fallback).
  static int desktopPort = defaultDesktopPort;
  static const int mobilePort = 8642;

  static String get coreBaseUrl {
    const envUrl = String.fromEnvironment('CORE_URL', defaultValue: '');
    if (envUrl.isNotEmpty) {
      return envUrl;
    }

    if (kIsWeb) {
      return '';
    }

    if (isMobilePlatform()) {
      return 'http://127.0.0.1:$mobilePort';
    }

    return 'http://127.0.0.1:$desktopPort';
  }

  static const int healthPollIntervalSeconds = 15;

  /// URL of the public KERI microservice used by MobileOnDeviceKeriService
  /// for stateless ACDC operations (/format-credential, /credential/present,
  /// /credential/verify) that keri_core v0.11 does not support natively.
  /// Can be overridden at compile-time via KERI_SERVICE_URL env variable.
  static const String publicKeriServiceUrl = String.fromEnvironment(
    'KERI_SERVICE_URL',
    defaultValue: 'https://keri.grapeid.org',
  );
}
