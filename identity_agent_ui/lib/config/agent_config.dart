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

  static const int healthPollIntervalSeconds = 15;
}
