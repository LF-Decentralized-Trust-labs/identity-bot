import 'package:flutter/foundation.dart' show kIsWeb;

class AgentConfig {
  static const String _defaultLocalPort = '5000';

  static String get coreBaseUrl {
    const envUrl = String.fromEnvironment('CORE_URL', defaultValue: '');
    if (envUrl.isNotEmpty) {
      return envUrl;
    }

    if (kIsWeb) {
      return '';
    }

    return 'http://localhost:$_defaultLocalPort';
  }

  static String get primaryServerUrl {
    const url = String.fromEnvironment('PRIMARY_SERVER_URL', defaultValue: '');
    return url;
  }

  static String get keriHelperUrl {
    const url = String.fromEnvironment('KERI_HELPER_URL', defaultValue: '');
    return url;
  }

  static const int healthPollIntervalSeconds = 15;
}
