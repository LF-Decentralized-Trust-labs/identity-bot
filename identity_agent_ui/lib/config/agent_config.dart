import 'package:flutter/foundation.dart' show kIsWeb;
import 'platform_helper_stub.dart'
    if (dart.library.io) 'platform_helper_io.dart';

class AgentConfig {
  static const int desktopPort = 5000;
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

    return 'http://localhost:$desktopPort';
  }

  static const int healthPollIntervalSeconds = 15;
}
