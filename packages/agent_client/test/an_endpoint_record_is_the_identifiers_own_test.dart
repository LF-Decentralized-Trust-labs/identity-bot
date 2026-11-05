import 'dart:convert';
import 'dart:io';

import 'package:agent_client/crypto/endpoint_record.dart';
import 'package:test/test.dart';

/// The vectors are the Go package's file, read in place: Go and Dart agree on
/// them or one of the two tests fails. Run from packages/agent_client.
Map<String, dynamic> _vectors() {
  final file = File(
      '../../identity-agent-core/endpointrecord/endpoint-record-vectors.json');
  return jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
}

void main() {
  final v = _vectors();
  final now = DateTime.parse(v['now'] as String);
  final keys = {
    'public_key': v['public_key'] as String,
    'other_public_key': v['other_public_key'] as String,
    'next_public_key': v['next_public_key'] as String,
  };

  group('every published record', () {
    for (final r in (v['records'] as List).cast<Map<String, dynamic>>()) {
      test(r['name'] as String, () {
        final check = verifyEndpointRecord(
            Map<String, dynamic>.from(r['record'] as Map), keys[r['key']]!,
            now: now,
            maxAge: r['max_age_days'] == null
                ? null
                : Duration(days: r['max_age_days'] as int));
        expect(check.valid, r['valid'], reason: check.reason);
        if (r['canonical'] != null) {
          expect(
              endpointRecordSignedBytes(
                  Map<String, dynamic>.from(r['record'] as Map)),
              r['canonical']);
        }
      });
    }
  });

  test('every published origin is in its one spelling or not', () {
    final origins = (v['origins'] as List).cast<Map<String, dynamic>>();
    expect(origins.length, greaterThan(30));
    for (final o in origins) {
      expect(originProblem(o['origin'] as String) == null, o['ok'],
          reason: 'origin ${o['origin']}: ${originProblem(o['origin'] as String)}');
    }
  });

  test('every published address becomes the origin Go makes of it', () {
    final addresses = (v['addresses'] as List).cast<Map<String, dynamic>>();
    expect(addresses.length, greaterThan(10));
    for (final a in addresses) {
      expect(canonicalOriginOf(a['address'] as String) ?? '', a['origin'],
          reason: 'address ${a['address']}');
    }
  });

  test('every published ordering', () {
    for (final o in (v['ordering'] as List).cast<Map<String, dynamic>>()) {
      expect(
          endpointRecordReplaces(
              {'aid': o['a_aid'], 'issued': o['a_issued']},
              {'aid': o['b_aid'], 'issued': o['b_issued']}),
          o['newer'],
          reason: o['name'] as String);
    }
  });

  test('a valid record says which origin, and a withdrawal says none', () {
    final records = (v['records'] as List).cast<Map<String, dynamic>>();
    final plain = records.firstWhere(
        (r) => r['name'] == 'an origin on the default port')['record'] as Map;
    final ok = verifyEndpointRecord(Map<String, dynamic>.from(plain), keys['public_key']!, now: now);
    expect(ok.origin, 'https://org.example.com:443');
    expect(ok.isWithdrawal, isFalse);
    final gone = records.firstWhere(
        (r) => r['name'] == 'a withdrawal, which names no address')['record'] as Map;
    final w = verifyEndpointRecord(Map<String, dynamic>.from(gone), keys['public_key']!, now: now);
    expect(w.isWithdrawal, isTrue);
  });

  test('an address becomes the origin the form writes', () {
    expect(canonicalOriginOf('https://Agent.Example.test'), 'https://agent.example.test:443');
    expect(canonicalOriginOf('http://localhost:8080/api/x?y=1'), 'http://localhost:8080');
    expect(canonicalOriginOf('https://[2001:DB8::1]:9'), 'https://[2001:db8::1]:9');
    expect(canonicalOriginOf('ftp://x.example'), isNull);
    expect(canonicalOriginOf('https://u:p@x.example'), isNull);
  });
}
