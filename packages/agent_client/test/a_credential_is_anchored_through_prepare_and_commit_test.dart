import 'dart:convert';

import 'package:agent_client/crypto/owner_signature.dart';
import 'package:agent_client/services/key_math.dart';
import 'package:agent_client/services/local_core_keri_service.dart';
import 'package:agent_client/services/secure_key_store.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:test/test.dart';

import 'support/a_core_that_misleads.dart';
import 'support/the_core.dart';

void main() {
  late String bin;
  late KeyMath km;
  late ACore core;
  const words =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const schema = 'Eschema';
  const holder = 'Eholder';

  setUpAll(() async {
    bin = await buildTheCore('credential-core', dev: true);
    km = await keyMathOf(bin);
  });

  setUp(() async {
    FlutterSecureStorage.setMockInitialValues({});
    SecureKeyStore.holdPhraseWith(InMemoryPhraseHolder());
    SharedPreferences.setMockInitialValues({});
    core = await anotherCore(bin, km);
  });

  tearDown(() => core.close());

  LocalCoreKeriService service() => LocalCoreKeriService(
      baseUrl: core.base, client: core.client, keyMath: km);

  int count(String request) =>
      core.client.visited.where((v) => v == request).length;

  // What the founding itself committed and signed.
  var commitsAtFounding = 0;

  Future<String> founded() async {
    await SecureKeyStore.saveMnemonic(words.split(' '));
    final aid = (await service().inceptAid(name: 'me', code: words)).aid;
    commitsAtFounding = count('POST /api/events/commit');
    return aid;
  }

  Future<Map<String, dynamic>> get(String path) async => jsonDecode((await http
          .get(Uri.parse('${core.base}$path'),
              headers: const {'X-Local-Owner-Secret': ownerSecret}))
      .body) as Map<String, dynamic>;

  Future<List<dynamic>> kept() async =>
      (await get('/api/credentials'))['credentials'] as List;

  Future<Map<String, dynamic>> prepared(
      {Map<String, dynamic> claims = const {'name': 'Ada'},
      String forSchema = schema,
      String to = holder}) async {
    final res = await http.post(Uri.parse('${core.base}/api/credential/prepare'),
        headers: const {
          'Content-Type': 'application/json',
          'X-Local-Owner-Secret': ownerSecret
        },
        body: jsonEncode(
            {'claims': claims, 'schema_said': forSchema, 'holder_aid': to}));
    expect(res.statusCode, 200, reason: res.body);
    return jsonDecode(res.body) as Map<String, dynamic>;
  }

  /// Nothing was anchored, signed or kept.
  Future<void> nothingAnchored(String aid) async {
    expect((await get('/api/kel?name=$aid'))['event_count'], 1,
        reason: 'the key log holds only its founding');
    expect(count('POST /api/events/commit'), commitsAtFounding);
    expect(await kept(), isEmpty);
  }

  test(
      'an identity whose keys this device holds issues a credential the core '
      'accepts, anchored by an interaction this device signed', () async {
    final aid = await founded();
    final issued = await service().issueCredential(
        claims: {'name': 'Ada'}, schemaSaid: schema, holderAid: holder);

    final log = await get('/api/kel?name=$aid');
    expect(log['event_count'], 2);
    final ixn = (log['kel'] as List).last as Map;
    expect(ixn['t'], 'ixn');
    expect(ixn['a'], [
      {'i': issued.acdcSaid, 's': '0', 'd': issued.acdcSaid}
    ]);
    expect(ixn['d'], issued.ixnSaid);
    expect(log['signed'], [true, true]);
    final credential = (await kept()).single as Map;
    expect(credential['said'], issued.acdcSaid);
    expect(credential['issuer_aid'], aid);
    expect(credential['holder_aid'], holder);
    final read = await km.checkCredential(base64Decode(issued.acdcJsonB64));
    expect(read.said, issued.acdcSaid);
    expect(read.issuer, aid);
  });

  test(
      'a core that returns another credential body, or a different identifier, '
      'gets nothing signed', () async {
    final aid = await founded();
    final other = await prepared(claims: {'name': 'Eve'});

    core.client.alterTheAnswerTo['/api/credential/prepare'] =
        (a) => {...a, 'acdc_json_b64': other['acdc_json_b64']};
    await expectLater(
        service().issueCredential(
            claims: {'name': 'Ada'}, schemaSaid: schema, holderAid: holder),
        throwsA(isA<NotTheCredentialAsked>()));
    await nothingAnchored(aid);

    // The body is the one asked for; the identifier the core names is not its.
    core.client.alterTheAnswerTo['/api/credential/prepare'] =
        (a) => {...a, 'acdc_said': other['acdc_said']};
    await expectLater(
        service().issueCredential(
            claims: {'name': 'Ada'}, schemaSaid: schema, holderAid: holder),
        throwsA(isA<NotTheCredentialAsked>()));
    await nothingAnchored(aid);

    // A credential that digests correctly but is another holder's, another
    // schema's, or says more than was asked.
    for (final wrong in [
      await prepared(to: 'Esomebodyelse'),
      await prepared(forSchema: 'Eanotherschema'),
      await prepared(claims: {'name': 'Ada', 'admin': true}),
      await prepared(to: ''),
    ]) {
      core.client.alterTheAnswerTo['/api/credential/prepare'] = (a) => {
            ...a,
            'acdc_json_b64': wrong['acdc_json_b64'],
            'acdc_said': wrong['acdc_said']
          };
      await expectLater(
          service().issueCredential(
              claims: {'name': 'Ada'}, schemaSaid: schema, holderAid: holder),
          throwsA(isA<NotTheCredentialAsked>()));
      await nothingAnchored(aid);
    }
  });

  /// The credential [prepared] answered, changed by [change] and identified
  /// again, as a core that wants other terms anchored would send it: its
  /// attribute block and the whole each the digest of what they now hold.
  Map<String, dynamic> reidentified(Map<String, dynamic> prepared,
      void Function(Map<String, dynamic> sad) change) {
    final sad = jsonDecode(utf8.decode(base64Decode(prepared['acdc_json_b64'])))
        as Map<String, dynamic>;
    change(sad);
    String digestOf(Map<String, dynamic> m) =>
        OwnerSignature.blake3QB64(utf8.encode(jsonEncode(m)));
    final blank = '#' * 44;
    final a = sad['a'] as Map<String, dynamic>;
    a['d'] = blank;
    a['d'] = digestOf(a);
    sad['d'] = blank;
    final length = utf8.encode(jsonEncode(sad)).length;
    sad['v'] = 'ACDC10JSON${length.toRadixString(16).padLeft(6, '0')}_';
    sad['d'] = blank;
    sad['d'] = digestOf(sad);
    return {
      ...prepared,
      'acdc_json_b64': base64Encode(utf8.encode(jsonEncode(sad))),
      'acdc_said': sad['d'],
    };
  }

  test(
      'a core that adds terms the device never asked for, or dates a credential '
      'long ago, gets nothing signed', () async {
    final aid = await founded();
    final real = await prepared();
    Map<String, dynamic> put(Map<String, dynamic> sad, String name, Object v) {
      // After the schema, as a core that wanted it read would place it.
      final tail = Map<String, dynamic>.of(sad)
        ..removeWhere((k, _) => const {'v', 'd', 'i', 's'}.contains(k));
      sad.removeWhere((k, _) => !const {'v', 'd', 'i', 's'}.contains(k));
      sad[name] = v;
      sad.addAll(tail);
      return sad;
    }

    final hostile = <String, Map<String, dynamic>>{
      'a rules block': reidentified(
          real,
          (sad) =>
              put(sad, 'r', {'d': '', 'waiver': 'the issuer owes nothing'})),
      'an unknown field': reidentified(real, (sad) => put(sad, 'z', 'terms')),
      'an event type': reidentified(real, (sad) => put(sad, 't', 'iss')),
      'a date long ago': reidentified(
          real,
          (sad) => (sad['a'] as Map<String, dynamic>)['dt'] = DateTime.now()
              .toUtc()
              .subtract(const Duration(days: 30))
              .toIso8601String()),
    };
    for (final entry in hostile.entries) {
      core.client.alterTheAnswerTo['/api/credential/prepare'] = (a) => {
            ...a,
            'acdc_json_b64': entry.value['acdc_json_b64'],
            'acdc_said': entry.value['acdc_said']
          };
      await expectLater(
          service().issueCredential(
              claims: {'name': 'Ada'}, schemaSaid: schema, holderAid: holder),
          throwsA(isA<NotTheCredentialAsked>().having(
              (e) => e.toString(),
              'the reason',
              contains(switch (entry.key) {
                'a date long ago' => 'time of issue',
                'an event type' => 'event type',
                _ => 'field that was not asked for',
              }))),
          reason: entry.key);
      await nothingAnchored(aid);
    }

    // The control: the same re-identifying, changing nothing, is accepted, so
    // the refusals above are of what was changed and not of how it was made.
    final same = reidentified(real, (_) {});
    core.client.alterTheAnswerTo['/api/credential/prepare'] = (a) => {
          ...a,
          'acdc_json_b64': same['acdc_json_b64'],
          'acdc_said': same['acdc_said']
        };
    final issued = await service().issueCredential(
        claims: {'name': 'Ada'}, schemaSaid: schema, holderAid: holder);
    expect(issued.acdcSaid, same['acdc_said']);
  });

  /// What the core's engine says of a credential, with [change] applied: an
  /// older keymath, or one that is lying.
  KeyMath keyMathAnswering(
          Map<String, dynamic> Function(Map<String, dynamic>) change) =>
      _Answering(km, change);

  Future<void> altered(Map<String, dynamic> credential) async {
    core.client.alterTheAnswerTo['/api/credential/prepare'] = (a) => {
          ...a,
          'acdc_json_b64': credential['acdc_json_b64'],
          'acdc_said': credential['acdc_said']
        };
  }

  test(
      'a time of issue is read only in the form the core writes: RFC 3339 with '
      'an offset and every field in range, never as this device\'s local time',
      () async {
    final aid = await founded();
    final real = await prepared();
    final now = DateTime.now().toUtc();
    String two(int n) => n.toString().padLeft(2, '0');
    final day = '${now.year}-${two(now.month)}-${two(now.day)}';
    final clock = '${two(now.hour)}:${two(now.minute)}:${two(now.second)}';
    final compact = '${now.year}${two(now.month)}${two(now.day)}'
        'T${two(now.hour)}${two(now.minute)}${two(now.second)}Z';
    final refused = <String, String>{
      'no offset, so local time': '${day}T$clock',
      'a space for the T': '$day $clock' 'Z',
      'compact digits': compact,
      'an expanded year': '+${now.year}-${two(now.month)}-${two(now.day)}'
          'T${clock}Z',
      'nanoseconds': '${day}T$clock.123456789Z',
      // Out of range, which Dart's parser rolls over: an hour ago at minute
      // 60 or more is now, and would pass the clock check.
      'a minute out of range': () {
        final hourAgo = now.subtract(const Duration(hours: 1));
        return '${hourAgo.year}-${two(hourAgo.month)}-${two(hourAgo.day)}'
            'T${two(hourAgo.hour)}:${now.minute + 60}:${two(now.second)}Z';
      }(),
      'an offset out of range': '${day}T$clock+99:99',
      'a day the month does not have': '${now.year}-02-30T${clock}Z',
    };
    for (final entry in refused.entries) {
      await altered(reidentified(real,
          (sad) => (sad['a'] as Map<String, dynamic>)['dt'] = entry.value));
      await expectLater(
          service().issueCredential(
              claims: {'name': 'Ada'}, schemaSaid: schema, holderAid: holder),
          throwsA(isA<NotTheCredentialAsked>()
              .having((e) => e.toString(), 'the reason', contains('RFC 3339'))),
          reason: entry.key);
      await nothingAnchored(aid);
    }
    // The forms the core writes are taken: an offset, and Z.
    for (final ok in ['${day}T$clock.000000+00:00', '${day}T${clock}Z']) {
      await altered(reidentified(
          real, (sad) => (sad['a'] as Map<String, dynamic>)['dt'] = ok));
      expect(
          (await service().issueCredential(
                  claims: {'name': 'Ada'},
                  schemaSaid: schema,
                  holderAid: holder))
              .acdcSaid,
          isNotEmpty,
          reason: ok);
    }
  });

  test(
      'a time of issue far from this device\'s clock is said to be a '
      'disagreement of clocks, not a wrong credential', () async {
    final aid = await founded();
    await altered(reidentified(
        await prepared(),
        (sad) => (sad['a'] as Map<String, dynamic>)['dt'] = DateTime.now()
            .toUtc()
            .add(const Duration(hours: 3))
            .toIso8601String()));
    await expectLater(
        service().issueCredential(
            claims: {'name': 'Ada'}, schemaSaid: schema, holderAid: holder),
        throwsA(isA<NotTheCredentialAsked>()
            .having((e) => e.toString(), 'the reason', contains('disagree'))));
    await nothingAnchored(aid);
  });

  test(
      'an answer that does not say which fields a credential carries is not '
      'taken to mean it carries no more', () async {
    final aid = await founded();
    final withoutFields = LocalCoreKeriService(
        baseUrl: core.base,
        client: core.client,
        keyMath: keyMathAnswering((a) => {...a}..remove('fields')));
    await expectLater(
        withoutFields.issueCredential(
            claims: {'name': 'Ada'}, schemaSaid: schema, holderAid: holder),
        throwsA(isA<NotTheCredentialAsked>()
            .having((e) => e.toString(), 'the reason', contains('fields'))));
    await nothingAnchored(aid);
  });

  test(
      'the seal signed is the credential this device read, never the core\'s '
      'choice: a delegation approval is not signed as a credential', () async {
    final aid = await founded();
    // The core offers a delegate's identifier as the credential's: the seal an
    // approval of a delegation would carry.
    core.client.alterTheAnswerTo['/api/credential/prepare'] = (a) =>
        {...a, 'acdc_said': 'EDelegateEDelegateEDelegateEDelegateEDel'};
    await expectLater(
        service().issueCredential(
            claims: {'name': 'Ada'}, schemaSaid: schema, holderAid: holder),
        throwsA(isA<NotTheCredentialAsked>()));
    await nothingAnchored(aid);
  });

  test(
      'a presentation of another credential, or bytes that are a key event, '
      'are not signed', () async {
    final aid = await founded();
    final issued = await service().issueCredential(
        claims: {'name': 'Ada'}, schemaSaid: schema, holderAid: holder);

    final ok = await service().presentCredential(
        acdcSaid: issued.acdcSaid, holderAid: holder, issuerAid: aid);
    expect(ok.cesrSignature, isNotEmpty);
    final presented =
        await km.checkPresentation(base64Decode(ok.presentationJsonB64));
    expect(presented.credential, issued.acdcSaid);
    expect(presented.holder, holder);

    final commitsBefore = count('POST /api/events/commit');

    // A presentation of a credential that was not asked for.
    final res = await http.post(Uri.parse('${core.base}/api/credential/present'),
        headers: const {
          'Content-Type': 'application/json',
          'X-Local-Owner-Secret': ownerSecret
        },
        body: jsonEncode({
          'acdc_said': 'EAnotherCredentialEAnotherCredentialEAnoth',
          'holder_aid': holder,
          'issuer_aid': aid
        }));
    final other = jsonDecode(res.body) as Map<String, dynamic>;
    core.client.alterTheAnswerTo['/api/credential/present'] = (a) => {
          ...a,
          'presentation_json_b64': other['presentation_json_b64'],
          'presentation_said': other['presentation_said'],
          'pres_said_b64': other['pres_said_b64'],
        };
    await expectLater(
        service().presentCredential(
            acdcSaid: issued.acdcSaid, holderAid: holder, issuerAid: aid),
        throwsA(isA<NotThePresentationAsked>()));

    // The bytes to sign are a key event of this identity: the next interaction.
    final event = base64Encode(utf8.encode(jsonEncode(
        {'t': 'ixn', 'i': aid, 's': '2', 'p': issued.ixnSaid, 'a': []})));
    core.client.alterTheAnswerTo['/api/credential/present'] =
        (a) => {...a, 'pres_said_b64': event};
    await expectLater(
        service().presentCredential(
            acdcSaid: issued.acdcSaid, holderAid: holder, issuerAid: aid),
        throwsA(isA<NotThePresentationAsked>()));

    // The presentation itself is a key event.
    core.client.alterTheAnswerTo['/api/credential/present'] =
        (a) => {...a, 'presentation_json_b64': event, 'pres_said_b64': event};
    await expectLater(
        service().presentCredential(
            acdcSaid: issued.acdcSaid, holderAid: holder, issuerAid: aid),
        throwsA(isA<NotThePresentationAsked>()));

    expect(count('POST /api/events/commit'), commitsBefore,
        reason: 'nothing was signed or recorded');
  });

  test('no owner-route read is on a signing path', () async {
    final aid = await founded();
    // The routes that once told this device which key was in force, and the one
    // that took a signature for an event the core had already added.
    core.client.failOn.addAll(
        {'/api/identity', '/api/kel', '/api/events/signature', '/api/interact'});
    final issued = await service().issueCredential(
        claims: {'name': 'Ada'}, schemaSaid: schema, holderAid: holder);
    final presented = await service().presentCredential(
        acdcSaid: issued.acdcSaid, holderAid: holder, issuerAid: aid);
    expect(presented.cesrSignature, isNotEmpty);
    expect(
        core.client.visited
            .where((v) => v.startsWith('GET /api/kel') ||
                v == 'GET /api/identity' ||
                v == 'POST /api/events/signature'),
        isEmpty);
  });
}

/// A keymath whose answers to check_credential are changed by [change].
class _Answering implements KeyMath {
  _Answering(this._real, this._change);
  final KeyMath _real;
  final Map<String, dynamic> Function(Map<String, dynamic>) _change;

  @override
  Future<Map<String, dynamic>> run(
      String op, Map<String, dynamic> request) async {
    final answer = await _real.run(op, request);
    return op == 'check_credential' ? _change(answer) : answer;
  }
}
