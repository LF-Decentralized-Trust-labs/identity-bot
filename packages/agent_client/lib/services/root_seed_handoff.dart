import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

import '../config/agent_config.dart';
import '../crypto/bip39.dart';
import 'the_owner_at_this_computer.dart';

/// One root of trust: the mnemonic. The client generates and holds the phrase;
/// the local core derives every HD key (pairwise contacts, login relationships,
/// asset signing, audit signing, the credential vault) from a root seed. This
/// handoff makes those the SAME root: after identity creation or recovery, the
/// standard BIP39 seed of the phrase is posted once to the local core's
/// keystore, so the phrase alone recovers everything on any platform. The core
/// never sees the words, only the derived 64-byte seed; the core refuses to
/// replace an established different seed (409).
/// The core refused to hold this person's root seed on this device (HTTP 412):
/// its secure hardware cannot protect the seed, and a production build will not
/// write one it cannot. Thrown by [RootSeedHandoff.register] and never
/// swallowed, because carrying on would leave the core to keep a seed of its
/// own unprotected, which is the thing refused. [message] is the core's reason,
/// in words to show the person.
class RootSeedRefused implements Exception {
  RootSeedRefused(this.message);
  final String message;
  @override
  String toString() => message;
}

class RootSeedHandoff {
  /// Whether a core URL is this device's own.
  ///
  /// Deliberately strict: anything that is not plainly a loopback address is
  /// treated as remote. Being wrong in that direction costs a refused handoff
  /// and a log line; being wrong the other way puts the user's root key on
  /// somebody else's machine.
  static bool isLocalCore(String url) {
    final uri = Uri.tryParse(url);
    if (uri == null) return false;
    final host = uri.host.toLowerCase();
    return host == 'localhost' ||
        host == '127.0.0.1' ||
        host == '::1' ||
        host == '[::1]';
  }

  /// Posts the mnemonic-derived seed to the local core. Returns true when the
  /// seed is established (stored now or already identical). Other failures are
  /// logged, never thrown — onboarding must not break on a keystore hiccup.
  ///
  /// A 412 is the exception and throws [RootSeedRefused]: it is the core saying
  /// this device cannot protect the seed, so the person has to be told rather
  /// than the app carrying on.
  static Future<bool> register(
    List<String> mnemonic, {
    String? baseUrl,
    http.Client? client,
  }) async {
    // THIS COMPUTER, deliberately. A handoff gives the seed to the core beside
    // you; sending it to an agent elsewhere would put a root seed on a machine
    // that is not meant to hold one — and a controller has no root seed to hand
    // over in the first place.
    final url = baseUrl ?? AgentConfig.coreBaseUrl;

    // A LOCAL core only. This posts the root seed itself, which is correct when
    // the core is on this device — same machine, same trust boundary — and
    // catastrophic when it is not: the seed derives every key the identity will
    // ever have, and sending it to hardware somebody else operates cannot be
    // undone by unpairing or by deleting the instance.
    //
    // A remote agent gets a DELEGATION instead, through /api/pairing/adopt: it
    // mints its own key, the root signs over it, and the root never moves.
    if (!isLocalCore(url)) {
      debugPrint('[RootSeedHandoff] refusing to send the root seed to a remote '
          'core at $url — a remote agent is adopted with a delegation, not '
          'given the seed');
      return false;
    }

    final c = ProvingThisComputer.over(client);
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
      if (resp.statusCode == 412) throw RootSeedRefused(_reasonIn(resp.body));
      return false;
    } on RootSeedRefused {
      rethrow;
    } catch (e) {
      debugPrint('[RootSeedHandoff] seed handoff failed: $e');
      return false;
    } finally {
      if (client == null) c.close();
    }
  }

  static String _reasonIn(String body) {
    try {
      final j = jsonDecode(body);
      if (j is Map && j['error'] is String && (j['error'] as String).isNotEmpty) {
        return j['error'] as String;
      }
    } catch (_) {}
    return 'this device cannot protect your identity\'s root key, so none was stored';
  }
}
