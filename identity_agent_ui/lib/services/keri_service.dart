import 'dart:io' show Platform;
import 'package:flutter/foundation.dart' show kIsWeb;

enum AgentEnvironment {
  desktop,
  mobileStandalone,
  mobileRemoteWithKeys,
  mobileRemoteWithoutKeys,
}

class InceptionResult {
  final String aid;
  final String publicKey;
  final String kel;
  final String created;

  InceptionResult({
    required this.aid,
    required this.publicKey,
    required this.kel,
    required this.created,
  });
}

class RotationResult {
  final String aid;
  final String newPublicKey;
  final String kel;

  RotationResult({
    required this.aid,
    required this.newPublicKey,
    required this.kel,
  });
}

class SignatureResult {
  final String signature;
  final String publicKey;

  SignatureResult({
    required this.signature,
    required this.publicKey,
  });
}

abstract class KeriService {
  AgentEnvironment get environment;

  Future<InceptionResult> inceptAid({
    required String name,
    required String code,
  });

  Future<RotationResult> rotateAid({
    required String name,
  });

  Future<SignatureResult> signPayload({
    required String name,
    required List<int> data,
  });

  Future<String> getCurrentKel({
    required String name,
  });

  Future<bool> verifySignature({
    required List<int> data,
    required String signature,
    required String publicKey,
  });

  void dispose();

  static AgentEnvironment detectEnvironment({
    String? primaryServerUrl,
    bool hasLocalKeys = false,
  }) {
    if (kIsWeb) {
      return AgentEnvironment.desktop;
    }

    final isMobile = Platform.isAndroid || Platform.isIOS;

    if (!isMobile) {
      return AgentEnvironment.desktop;
    }

    if (primaryServerUrl != null && primaryServerUrl.isNotEmpty) {
      return hasLocalKeys
          ? AgentEnvironment.mobileRemoteWithKeys
          : AgentEnvironment.mobileRemoteWithoutKeys;
    }

    return AgentEnvironment.mobileStandalone;
  }
}
