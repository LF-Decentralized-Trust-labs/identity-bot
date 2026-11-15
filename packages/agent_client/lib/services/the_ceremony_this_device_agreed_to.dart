import 'dart:async';
import 'dart:convert';

import 'package:crypto/crypto.dart' as crypto;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;

import 'key_math.dart';
import 'signing_a_ceremony_rotation.dart';
import 'the_event_this_device_expects.dart';

/// One owner as the ownership ceremony's terms name them.
class CeremonyTermsOwner {
  const CeremonyTermsOwner({
    required this.name,
    required this.aid,
    required this.key,
    required this.next,
    this.nextKey = '',
    this.after = const [],
    this.signed = false,
  });
  final String name;
  final String aid;
  final String key;
  final List<String> next;
  final String nextKey;
  final List<String> after;

  /// This owner's device has signed the rotation now waiting.
  final bool signed;

  factory CeremonyTermsOwner.fromJson(Map<String, dynamic> j) =>
      CeremonyTermsOwner(
        name: '${j['name'] ?? ''}',
        aid: '${j['aid'] ?? ''}',
        key: '${j['key'] ?? ''}',
        next: [for (final d in (j['next'] as List? ?? const [])) '$d'],
        nextKey: '${j['next_key'] ?? ''}',
        after: [for (final d in (j['after'] as List? ?? const [])) '$d'],
        signed: j['signed'] == true,
      );

  CeremonyOwner get asOwner =>
      CeremonyOwner(key, next, nextKey: nextKey, after: after);
}

/// What an ownership ceremony says it is about to do, as the organisation's
/// agent tells an invited owner's device: who is taking part, how many must sign
/// afterwards, whether the organisation's own key is being dropped, and the
/// rotation waiting.
class CeremonyTerms {
  const CeremonyTerms({
    required this.stage,
    required this.handOver,
    required this.threshold,
    required this.aid,
    required this.sn,
    required this.prior,
    required this.digest,
    required this.ownKey,
    required this.ownNextDigest,
    required this.toad,
    required this.cuts,
    required this.adds,
    required this.anchors,
    required this.owners,
  });

  final CeremonyStage stage;
  final bool handOver;
  final int threshold;
  final String aid;
  final int sn;
  final String prior;
  final String digest;
  final String ownKey;
  final String ownNextDigest;
  final int toad;
  final List<String> cuts;
  final List<String> adds;
  final List<Object?> anchors;
  final List<CeremonyTermsOwner> owners;

  factory CeremonyTerms.fromJson(Map<String, dynamic> j) {
    final stage = '${j['stage']}';
    return CeremonyTerms(
      stage: CeremonyStage.values.firstWhere((s) => s.wire == stage,
          orElse: () => throw FormatException('an unknown rotation "$stage"')),
      handOver: j['hand_over'] == true,
      threshold: (j['threshold'] as num).toInt(),
      aid: '${j['aid']}',
      sn: int.parse('${j['sn']}', radix: 16),
      prior: '${j['prior']}',
      digest: '${j['d']}',
      ownKey: '${j['own_key']}',
      ownNextDigest: '${j['own_next_digest'] ?? ''}',
      toad: int.tryParse('${j['toad'] ?? '0'}', radix: 16) ?? 0,
      cuts: [for (final c in (j['cuts'] as List? ?? const [])) '$c'],
      adds: [for (final c in (j['adds'] as List? ?? const [])) '$c'],
      anchors: List<Object?>.from(j['anchors'] as List? ?? const []),
      owners: [
        for (final o in (j['owners'] as List? ?? const []))
          CeremonyTermsOwner.fromJson(Map<String, dynamic>.from(o as Map))
      ],
    );
  }

  /// Everyone, by identifier, as the rotation is to be checked against.
  Map<String, CeremonyOwner> get ownerMap =>
      {for (final o in owners) o.aid: o.asOwner};

  /// How many owners' devices have signed the rotation waiting.
  int get signedCount => owners.where((o) => o.signed).length;

  /// The rotation this device is to expect, for [me], its identifier among the
  /// owners.
  ExpectedEvent expectedFor(String me) => ExpectedEvent.asAnOwnerInACeremony(
        stage: stage,
        handOver: handOver,
        aid: aid,
        sn: sn,
        prior: prior,
        ownKey: ownKey,
        ownNextDigest: ownNextDigest.isEmpty ? null : ownNextDigest,
        owners: ownerMap,
        me: me,
        threshold: threshold,
        anchors: anchors,
        toad: toad,
        cuts: cuts,
        adds: adds,
      );
}

/// What the person agreed to when they were shown the first rotation and said to
/// sign it: the owners and their keys, the threshold, and whether this is a
/// hand-over. The second rotation of a hand-over is signed only if it is made
/// of exactly this, so a core cannot change who the owners are between the two.
class CeremonyAgreement {
  const CeremonyAgreement(this._j);
  final Map<String, dynamic> _j;

  factory CeremonyAgreement.of(CeremonyTerms t) => CeremonyAgreement({
        'aid': t.aid,
        'hand_over': t.handOver,
        'threshold': t.threshold,
        'own_key': t.ownKey,
        'owners': {
          for (final o in t.owners)
            o.aid: {
              'key': o.key,
              'next': o.next,
              'next_key': o.nextKey,
              'after': o.after,
            }
        },
      });

  factory CeremonyAgreement.fromJson(String s) =>
      CeremonyAgreement(Map<String, dynamic>.from(jsonDecode(s) as Map));
  String toJson() => jsonEncode(_j);

  /// What differs between this and [t], in words, or null when nothing does.
  String? differenceFrom(CeremonyTerms t) {
    final now = CeremonyAgreement.of(t)._j;
    for (final k in ['aid', 'hand_over', 'threshold', 'own_key']) {
      if ('${_j[k]}' != '${now[k]}') return 'the $k of the ceremony changed';
    }
    if (jsonEncode(_sorted(_j['owners'])) != jsonEncode(_sorted(now['owners']))) {
      return 'the owners, or their keys, are not the ones you agreed to';
    }
    return null;
  }

  static Object? _sorted(Object? v) => v is Map
      ? {for (final k in (v.keys.toList()..sort())) '$k': _sorted(v[k])}
      : v is List
          ? [for (final e in v) _sorted(e)]
          : v;
}

/// Where this device keeps what the person agreed to, between the two
/// rotations.
abstract class CeremonyAgreements {
  Future<CeremonyAgreement?> read(String token);
  Future<void> write(String token, CeremonyAgreement agreement);
}

class InMemoryCeremonyAgreements implements CeremonyAgreements {
  final Map<String, CeremonyAgreement> _m = {};
  @override
  Future<CeremonyAgreement?> read(String token) async => _m[token];
  @override
  Future<void> write(String token, CeremonyAgreement agreement) async =>
      _m[token] = agreement;
}

/// [CeremonyAgreements] in the device's secure storage, under a digest of the
/// invitation code (the code itself is a secret and is not a storage name).
class SecureCeremonyAgreements implements CeremonyAgreements {
  SecureCeremonyAgreements({FlutterSecureStorage? storage})
      : _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(encryptedSharedPreferences: true),
              mOptions: MacOsOptions(useDataProtectionKeyChain: false),
            );
  final FlutterSecureStorage _storage;

  String _name(String token) =>
      'ceremony_agreement_${crypto.sha256.convert(utf8.encode(token)).toString().substring(0, 32)}';

  @override
  Future<CeremonyAgreement?> read(String token) async {
    final raw = await _storage.read(key: _name(token));
    return raw == null || raw.isEmpty ? null : CeremonyAgreement.fromJson(raw);
  }

  @override
  Future<void> write(String token, CeremonyAgreement agreement) =>
      _storage.write(key: _name(token), value: agreement.toJson());
}

/// The core this device belongs to would not sign.
class CeremonyNotSigned implements Exception {
  CeremonyNotSigned(this.reason);
  final String reason;
  @override
  String toString() => reason;
}

/// What an ownership ceremony is doing, as an invited owner's device reads it.
class CeremonyReading {
  const CeremonyReading(this.status, this.terms);

  /// collecting (others have still to accept), signing, applied, failed or
  /// abandoned.
  final String status;

  /// The rotation waiting and who it is for; only while [status] is signing.
  final CeremonyTerms? terms;
}

/// An invited owner's side of an ownership ceremony: reading what it is to
/// agree to, and signing the rotation only when it is exactly that.
///
/// The organisation's agent is reached at [orgUrl], the address the invitation
/// was redeemed at; the key that signs is this device's own agent's, asked
/// through [signWithDeviceKey], so the key never leaves it.
class CeremonyDevice {
  CeremonyDevice({
    required this.client,
    required this.signWithDeviceKey,
    required this.km,
    CeremonyAgreements? agreements,
  }) : agreements = agreements ?? SecureCeremonyAgreements();

  /// Reaches the organisation's agent.
  final http.Client client;

  /// Asks this device's own agent for the signature its key owes
  /// (`CoreService.signACeremonyRotation`).
  final Future<List<int>> Function(String token,
      {required int generation, required List<int> raw}) signWithDeviceKey;
  final KeyMath km;
  final CeremonyAgreements agreements;

  /// Where the ceremony has got to, and, once everyone has accepted and there
  /// is a rotation to sign, what it is about. Null when the organisation knows
  /// no ceremony for this code.
  Future<CeremonyReading?> read(String orgUrl, String token) async {
    final res = await client.get(Uri.parse(
        '$orgUrl/api/signer/invites/${Uri.encodeComponent(token)}/ceremony-terms'));
    if (res.statusCode == 404) return null;
    if (res.statusCode != 200) {
      throw CeremonyNotSigned(
          'the organisation could not say what is to be signed (${res.statusCode})');
    }
    final j = Map<String, dynamic>.from(jsonDecode(res.body) as Map);
    final status = '${j['status'] ?? ''}';
    return CeremonyReading(
        status, status == 'signing' ? CeremonyTerms.fromJson(j) : null);
  }

  /// Signs the rotation in [terms], having the person's agreement to it.
  ///
  /// The first rotation records what the person was shown; the second must be
  /// made of the same owners. Nothing is signed for anything else.
  Future<CeremonySigned> sign(String orgUrl, String token, CeremonyTerms terms,
      {required String me}) async {
    if (terms.owners.every((o) => o.aid != me)) {
      throw CeremonyNotSigned('this device is not one of the owners named');
    }
    if (terms.stage == CeremonyStage.first) {
      await agreements.write(token, CeremonyAgreement.of(terms));
    } else {
      final agreed = await agreements.read(token);
      if (agreed == null) {
        throw CeremonyNotSigned(
            'this device was not shown the first rotation of this change, so it will not sign the second');
      }
      final why = agreed.differenceFrom(terms);
      if (why != null) throw CeremonyNotSigned(why);
    }
    return signTheCeremonyRotation(
      client,
      orgUrl,
      token: token,
      stage: terms.stage,
      sign: (raw) => signWithDeviceKey(token,
          generation: terms.stage == CeremonyStage.first ? 0 : 1, raw: raw),
      km: km,
      expected: terms.expectedFor(me),
    );
  }
}
