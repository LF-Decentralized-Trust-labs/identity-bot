import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

import '../config/agent_config.dart';
import '../crypto/bip39.dart';

/// One root of trust: the mnemonic. The client generates and holds the phrase;
/// the local core derives every HD key (pairwise contacts, login relationships,
/// asset signing, audit signing, the credential vault) from a root seed. This
/// handoff makes those the SAME root: after identity creation or recovery, the
/// standard BIP39 seed of the phrase is posted once to the local core's
/// keystore, so the phrase alone recovers everything on any platform. The core
/// never sees the words, only the derived 64-byte seed; the core refuses to
/// replace an established different seed (409).
class RootSeedHandoff {
  /// Posts the mnemonic-derived seed to the local core. Returns true when the
  /// seed is established (stored now or already identical). Failures are
  /// logged, never thrown — onboarding must not break on a keystore hiccup;
  /// the core falls back to a device-local root until a handoff succeeds.
  static Future<bool> register(
    List<String> mnemonic, {
    String? baseUrl,
    http.Client? client,
  }) async {
    final url = baseUrl ?? AgentConfig.coreBaseUrl;
    final c = client ?? http.Client();
    try {
      final seed = Bip39.mnemonicToSeed(mnemonic);
      final resp = await c
          .post(
            Uri.parse('$url/api/keystore/root-seed'),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode({'seed_b64': base64Encode(seed)}),
          )
          .timeout(const Duration(seconds: 10));
      if (resp.statusCode == 200 || resp.statusCode == 201) {
        debugPrint('[RootSeedHandoff] root seed established with local core');
        return true;
      }
      debugPrint(
          '[RootSeedHandoff] core refused seed handoff (${resp.statusCode}): ${resp.body}');
      return false;
    } catch (e) {
      debugPrint('[RootSeedHandoff] seed handoff failed: $e');
      return false;
    } finally {
      if (client == null) c.close();
    }
  }
}
