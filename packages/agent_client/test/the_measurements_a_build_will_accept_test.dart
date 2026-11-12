import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:agent_client/config/accepted_measurements.dart';
import 'package:agent_client/config/measurement_list.dart';

/// What a build says it will accept, and that this package agrees with the Go
/// core on what a signed list means.
///
/// The Go package `identity-agent-core/measurementlist` owns the format. Its
/// committed vectors (`testdata/`) are read here, so the two implementations
/// are held to the same files and cannot drift apart unseen.
final _vectors = Directory('../../identity-agent-core/measurementlist/testdata');
const _keyId = 'test-publisher-1';
final _now = DateTime.utc(2026, 11, 12, 12);

Uint8List _file(String name) => File('${_vectors.path}/$name').readAsBytesSync();
String get _key => File('${_vectors.path}/publisher_key.hex').readAsStringSync().trim();

VerifiedMeasurementList _verify(Uint8List raw, {int min = 0, String seen = ''}) => verifyMeasurementList(raw,
    publisherKeyHex: _key, publisherKeyId: _keyId, now: _now, minSequence: min, seenDigest: seen);

void main() {
  test('the committed valid list verifies and names what the core names', () {
    final l = _verify(_file('valid.json'));
    expect(l.sequence, 7);
    expect(l.measurementsAt('individual', _now), isNotEmpty);
  });

  final manifest = jsonDecode(File('${_vectors.path}/negative/expectations.json').readAsStringSync()) as List;
  for (final v in manifest.cast<Map<String, dynamic>>()) {
    test('${v['file']}: ${v['note']}', () {
      final raw = _file('negative/${v['file']}');
      final min = (v['min_sequence'] as int?) ?? 0;
      final seen = (v['seen_digest'] as String?) ?? '';
      final refusal = v['refusal'] as String;
      if (refusal.isNotEmpty) {
        expect(() => _verify(raw, min: min, seen: seen),
            throwsA(isA<MeasurementListRefusal>().having((e) => e.code, 'code', refusal)));
      } else {
        expect(_verify(raw, min: min, seen: seen).measurementsAt('individual', _now).length, v['accepted_for_individual']);
      }
    });
  }

  test('a key whose private half is published is refused as the pinned key', () {
    expect(() => verifyMeasurementList(_file('valid.json'),
            publisherKeyHex: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
            publisherKeyId: _keyId, now: _now),
        throwsA(isA<MeasurementListRefusal>()));
  });

  test('a repeated key is refused, because two parsers would read different lists', () {
    final raw = utf8.encode(utf8.decode(_file('valid.json')).replaceFirst('{', '{"sequence":1,'));
    expect(() => _verify(Uint8List.fromList(raw)),
        throwsA(isA<MeasurementListRefusal>().having((e) => e.code, 'code', 'ErrMalformed')));
  });

  group('staging the list for the core', () {
    late Directory dir;
    setUp(() => dir = Directory.systemTemp.createTempSync('staged'));
    tearDown(() => dir.deleteSync(recursive: true));
    File staged() => File('${dir.path}/$stagedMeasurementListName');
    Future<int?> stage(List<MeasurementListSource> s, {String? key}) => stageMeasurementList(dir.path,
        now: _now, publisherKeyHex: key ?? _key, publisherKeyId: _keyId, sources: s);

    test('a verified list is written where the core reads it, byte for byte', () async {
      expect(await stage([() async => _file('valid.json')]), 7);
      expect(staged().readAsBytesSync(), _file('valid.json'));
    });

    test('a list that does not verify is never staged', () async {
      expect(await stage([() async => _file('negative/tampered.json')]), isNull);
      expect(staged().existsSync(), isFalse);
    });

    test('a bad fetch leaves the good staged list, and an offline one does too', () async {
      await stage([() async => _file('valid.json')]);
      expect(await stage([() async => _file('negative/tampered.json')]), 7);
      expect(await stage([() async => throw Exception('offline')]), 7);
      expect(await stage([() async => null]), 7);
      expect(staged().readAsBytesSync(), _file('valid.json'));
    });

    test('an older list does not replace the staged one', () async {
      await stage([() async => _file('valid.json')]);
      expect(await stage([() async => _file('negative/old_sequence.json')]), 7);
      expect(staged().readAsBytesSync(), _file('valid.json'));
    });

    test('a different list at the staged sequence does not replace it', () async {
      await stage([() async => _file('valid.json')]);
      expect(await stage([() async => _file('negative/same_sequence_different_content.json')]), 7);
      expect(staged().readAsBytesSync(), _file('valid.json'));
    });

    test('with no key pinned nothing is staged', () async {
      expect(await stage([() async => _file('valid.json')], key: ''), isNull);
      expect(staged().existsSync(), isFalse);
    });

    test('a source that fails is skipped for one that verifies', () async {
      expect(await stage([() async => throw Exception('offline'), () async => _file('valid.json')]), 7);
    });
  });
}
