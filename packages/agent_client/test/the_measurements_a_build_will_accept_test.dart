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

class _Floor implements MeasurementFloorStore {
  String? record;
  @override
  Future<String?> read() async => record;
  @override
  Future<void> write(String r) async => record = r;
}

Uint8List _file(String name) => File('${_vectors.path}/$name').readAsBytesSync();
String get _key => File('${_vectors.path}/publisher_key.hex').readAsStringSync().trim();

VerifiedMeasurementList _verify(Uint8List raw, {int min = 0}) => verifyMeasurementList(raw,
    publisherKeyHex: _key, publisherKeyId: _keyId, now: _now, minSequence: min);

void main() {
  test('a build told nothing accepts nothing', () async {
    expect(bootstrapMeasurements(), isEmpty,
        reason: 'no policy must mean adopt nothing, never adopt anything');
    expect(await acceptedMeasurements(kind: 'individual', floorStore: _Floor(), sources: []), isEmpty);
  });

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
      final refusal = v['refusal'] as String;
      if (refusal.isNotEmpty) {
        expect(() => _verify(raw, min: min),
            throwsA(isA<MeasurementListRefusal>().having((e) => e.code, 'code', refusal)));
      } else {
        expect(_verify(raw, min: min).measurementsAt('individual', _now).length, v['accepted_for_individual']);
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

  group('the device\'s policy', () {
    final bootstrap = ['aa' * 48];
    Future<List<String>> ask(_Floor f, List<MeasurementListSource> s, {String key = ''}) =>
        acceptedMeasurements(
            kind: 'individual', now: _now, publisherKeyHex: key.isEmpty ? _key : key,
            publisherKeyId: _keyId, sources: s, floorStore: f, bootstrap: bootstrap);

    test('a verified list is the policy, is recorded, and the bootstrap is not added', () async {
      final f = _Floor();
      final got = await ask(f, [() async => _file('valid.json')]);
      expect(got, isNotEmpty);
      expect(got, isNot(contains(bootstrap.first)));
      expect(f.record, startsWith('7 '));
    });

    test('with no list ever accepted the bootstrap stands', () async {
      expect(await ask(_Floor(), [() async => _file('negative/tampered.json')]), bootstrap);
    });

    test('once a list was accepted a failing list means nothing, never the bootstrap', () async {
      final f = _Floor();
      await ask(f, [() async => _file('valid.json')]);
      expect(await ask(f, [() async => _file('negative/tampered.json')]), isEmpty);
      expect(await ask(f, [() async => _file('negative/old_sequence.json')]), isEmpty);
      expect(await ask(f, [() async => null]), isEmpty);
      expect(await ask(f, [() async => throw Exception('offline')]), isEmpty);
    });

    test('a source that fails is skipped for one that verifies', () async {
      final got = await ask(_Floor(), [() async => throw Exception('offline'), () async => _file('valid.json')]);
      expect(got, isNotEmpty);
    });
  });
}
