import 'dart:convert';
import 'dart:typed_data';

import 'package:agent_client/models/what_the_watcher_found.dart';
import 'package:agent_client/services/core_service.dart';
import 'package:test/test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

// A client that signs as the owner, which is how a front end reaches its agent.
CoreService svc(Future<http.Response> Function(http.Request) h) => CoreService(
      baseUrl: 'http://core.test',
      ownerSeed: () async => Uint8List.fromList(List.filled(32, 7)),
      ownerAid: 'EOwner',
      inner: MockClient(h),
    );

void main() {
  test('a duplicity refusal is a typed error carrying the aid, not a bare message', () async {
    final core = svc((_) async => http.Response(
        jsonEncode({'error': 'KEL duplicity detected', 'details': 'L1 digest mismatch', 'code': 'duplicity', 'aid': 'EA'}), 409));
    await expectLater(
      core.resolveOobiContact(oobiUrl: 'http://x'),
      throwsA(isA<ContactRefusedForDuplicity>().having((e) => e.aid, 'aid', 'EA')),
    );
    await expectLater(core.addContact(oobiUrl: 'http://x'), throwsA(isA<ContactRefusedForDuplicity>()));
  });

  test('another 409 is still an ordinary error', () async {
    final core = svc((_) async => http.Response(jsonEncode({'error': 'Different realm'}), 409));
    await expectLater(core.resolveOobiContact(oobiUrl: 'http://x'), throwsA(isA<Exception>().having((e) => e is ContactRefusedForDuplicity, 'dup', false)));
  });

  test('alerts, checks and status are read; an unchecked contact is null, not confirmed', () async {
    final core = svc((r) async {
      if (r.url.path == '/api/watcher/alerts') {
        expect(r.url.queryParameters['open'], 'true');
        return http.Response(jsonEncode({'alerts': [{'id': 4, 'aid': 'EA', 'sequence_num': 3, 'detected_at': 't', 'acknowledged': false, 'resolved': false}]}), 200);
      }
      if (r.url.path == '/api/watcher/checks/EA') {
        return http.Response(jsonEncode({'aid': 'EA', 'checked_at': 't', 'verdict': 'confirmed', 'sources': [{'type': 'own_record', 'outcome': 'agrees'}]}), 200);
      }
      if (r.url.path.startsWith('/api/watcher/checks/')) return http.Response(jsonEncode({'error': 'not checked', 'code': 'never_checked'}), 404);
      if (r.url.path == '/api/watcher/status') return http.Response(jsonEncode({'running': true, 'state': 'own_record_only'}), 200);
      return http.Response('', 500);
    });
    final alerts = await core.getWatcherAlerts(onlyOpen: true);
    expect(alerts.single.isOpen, isTrue);
    final c = (await core.getWatcherCheck('EA'))!;
    expect(c.verdict, 'confirmed');
    expect(c.anotherWatcherAgreed, isFalse, reason: 'own memory agreeing with itself is not corroboration');
    expect(await core.getWatcherCheck('ENever'), isNull);
    expect((await core.getWatcherStatus()).state, 'own_record_only');
  });

  test('resolving sends the note and the trusted list is sent whole', () async {
    final seen = <String>[];
    final core = svc((r) async {
      seen.add('${r.method} ${r.url.path} ${r.body}');
      return http.Response('{}', 200);
    });
    await core.resolveWatcherAlert(4, note: 'they re-founded');
    await core.setTrustedWatchers([]);
    expect(seen, ['POST /api/watcher/alerts/4/resolve {"note":"they re-founded"}', 'PUT /api/watcher/trusted {"aids":[]}']);
  });

  test('a failed read is an error, never an empty list', () async {
    final core = svc((_) async => http.Response('{}', 500));
    await expectLater(core.getWatcherAlerts(), throwsException);
  });

  test('unverified and unchecked are different words, and only an open alert blocks', () {
    expect(contactTrustLabel(verified: true, status: 'accepted'), 'Verified');
    expect(contactTrustLabel(verified: false, status: 'unchecked'), 'Unchecked');
    expect(contactTrustLabel(verified: false, status: 'unverified'), 'Unverified');
    expect(
        aidsWithOpenAlerts(const [
          WatcherAlert(id: 1, aid: 'EA', sequenceNum: 1, detectedAt: 't'),
          WatcherAlert(id: 2, aid: 'EB', sequenceNum: 1, detectedAt: 't', acknowledged: true),
          WatcherAlert(id: 3, aid: 'EC', sequenceNum: 1, detectedAt: 't', resolved: true),
        ]),
        {'EA', 'EB'},
        reason: 'acknowledging does not clear an alert; resolving does');
  });

  test('with the watcher off the contact list has no blocked entries rather than failing', () async {
    final core = svc((_) async => http.Response(jsonEncode({'error': 'watcher not running', 'code': 'watcher_off'}), 404));
    expect(await core.getAidsWithOpenAlerts(), isEmpty);
    await expectLater(core.getWatcherCheck('EA'), throwsA(isA<WatcherNotRunning>()),
        reason: 'off must not read as never checked');
  });

  test('a real failure is not swallowed as no blocked contacts', () async {
    final core = svc((_) async => http.Response('boom', 500));
    await expectLater(core.getAidsWithOpenAlerts(), throwsException);
  });

  test('a proven fork carries its two signed events, and a flagged watcher says why', () async {
    final held = base64.encode(utf8.encode('event held'));
    final rival = base64.encode(utf8.encode('event rival'));
    final alerts = [
      {'id': 1, 'aid': 'EA', 'sequence_num': 3, 'detected_at': 't', 'kind': 'duplicity', 'source_url': 'https://w1',
        'evidence': {'kind': 'duplicity', 'sequence_number': 3, 'held_message_b64': held, 'rival_message_b64': rival, 'watcher': 'https://w1',
          'identifier': 'EA', 'prior_messages_b64': [base64.encode(utf8.encode('prior one'))],
          'events': [
            {'role': 'held', 'type': 'ixn', 'said': 'EHELDSAID', 'signing_keys': ['DKEYONE']},
            {'role': 'rival', 'type': 'ixn', 'said': 'ERIVALSAID', 'signing_keys': ['DKEYONE']},
          ]}},
      {'id': 2, 'aid': 'EB', 'sequence_num': 5, 'detected_at': 't', 'kind': 'watcher', 'source_url': 'https://w2',
        'evidence': {'kind': 'watcher', 'sequence_number': 5, 'watcher': 'https://w2', 'why': 'its log does not verify', 'why_code': 'log_does_not_verify'}},
      {'id': 3, 'aid': 'EC', 'sequence_num': 1, 'detected_at': 't', 'kind': 'escalation', 'source_url': 'https://w3'},
      {'id': 4, 'aid': 'ED', 'sequence_num': 2, 'detected_at': 't'},
      {'id': 5, 'aid': 'EB', 'sequence_num': 5, 'detected_at': 't', 'kind': 'watcher', 'source_url': 'https://w5',
        'evidence': {'kind': 'watcher', 'sequence_number': 5, 'watcher': 'https://w5', 'why': 'its log is for another identity', 'wrong_identity': true}},
    ];
    final core = svc((_) async => http.Response(jsonEncode({'alerts': alerts}), 200));
    final got = await core.getWatcherAlerts(onlyOpen: true);
    final fork = got[0].evidence!;
    expect(fork.hasBoth, isTrue);
    expect(fork.sequenceNumber, 3);
    expect(fork.watcher, 'https://w1');
    expect(fork.heldFingerprint, isNot(fork.rivalFingerprint));
    expect(fork.heldFingerprint, hasLength(12));
    expect(fork.copyText, allOf(contains(held), contains(rival), contains('Identity: EA'), contains(base64.encode(utf8.encode('prior one')))),
        reason: 'somebody else can only verify the two events with the history before them');
    expect(fork.heldDetail!.said, 'EHELDSAID');
    expect(fork.rivalDetail!.said, 'ERIVALSAID');
    expect(fork.heldDetail!.typeLabel, 'interaction');
    expect(fork.copyText, allOf(contains('interaction (ixn), SAID EHELDSAID, signed by DKEYONE'), contains('SAID ERIVALSAID')),
        reason: 'a person or a checker sees what forked without decoding the messages');
    expect(got[3].evidence, isNull);
    expect(got[1].isWatcherFlag, isTrue);
    expect(got[1].why, 'its log does not verify');
    expect(got[1].evidence, isNull);
    expect(got[1].wrongIdentity, isFalse);
    expect(got[1].whyCode, 'log_does_not_verify');
    expect(got[4].whyCode, '');
    expect(got[1].watcherFlagWords, 'its log does not verify', reason: 'a failed check keeps the core\'s sentence');
    expect(got[4].wrongIdentity, isTrue);
    expect(got[4].watcherFlagWords, allOf(contains('different identity'), isNot(contains('verify'))),
        reason: 'a watcher answering about someone else is not a failed signature');
    expect(got[3].kind, 'duplicity', reason: 'an alert with no kind is a duplicity alert');
    expect(got[3].evidence, isNull);
    // Only the proven fork holds its contact: a flagged watcher or an escalation blocks nothing.
    expect(aidsWithOpenAlerts(got), {'EA', 'ED'});
  });

  test('the status counts the flagged watchers beside the forks', () {
    final s = WatcherStatus.fromJson({'running': true, 'state': 'checking', 'open_alerts': 1, 'open_watcher_flags': 2});
    expect([s.openAlerts, s.openWatcherFlags], [1, 2]);
    expect(WatcherStatus.fromJson({'running': true}).openWatcherFlags, 0);
  });

  test('a watcher that was ahead agreed with the history, one that was faulty or behind did not', () {
    ContactWatchCheck check(String outcome) => ContactWatchCheck.fromJson({
          'aid': 'EA', 'checked_at': 't', 'verdict': 'confirmed',
          'sources': [{'type': 'own_record', 'outcome': 'agrees'}, {'type': 'standing', 'outcome': outcome}],
        });
    expect(check('ahead').anotherWatcherAgreed, isTrue);
    expect(check('faulty').anotherWatcherAgreed, isFalse);
    expect(check('behind').anotherWatcherAgreed, isFalse);
  });

  test('only a watcher the person trusts corroborates: one the contact named, or another contact\'s device, never does', () {
    ContactWatchCheck check(String type, String outcome) => ContactWatchCheck.fromJson({
          'aid': 'EA', 'checked_at': 't', 'verdict': 'confirmed',
          'sources': [{'type': 'own_record', 'outcome': 'agrees'}, {'type': type, 'outcome': outcome}],
        });
    for (final outcome in ['agrees', 'ahead']) {
      expect(check('standing', outcome).anotherWatcherAgreed, isTrue);
      // A forger names their own watcher: it agreeing proves nothing.
      expect(check('hint', outcome).anotherWatcherAgreed, isFalse);
      expect(check('peer', outcome).anotherWatcherAgreed, isFalse);
    }
  });

  test('the refusal says what the proof shows and offers no advice that does not work', () {
    const e = ContactRefusedForDuplicity(aid: 'EA', reason: 'x');
    expect(
        e.plainMessageFor('Sam Rivera'),
        'Whoever holds Sam Rivera\u2019s keys signed two different versions of the same event. '
        'Either they did this, or someone else has their keys. Do not trust this identity. '
        'Tell them by another way you trust.');
    expect(e.plainMessage, contains('this identity\u2019s keys'));
    for (final m in [e.plainMessage, e.plainMessageFor('Sam')]) {
      expect(m, isNot(contains('copied')));
      expect(m, isNot(contains('tampered')));
      expect(m, isNot(contains('fresh contact link')));
    }
  });
}
