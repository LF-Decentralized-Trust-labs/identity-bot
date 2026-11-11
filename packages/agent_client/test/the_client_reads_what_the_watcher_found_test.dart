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

  test('the refusal says what happened, what it means and what to do', () {
    final m = const ContactRefusedForDuplicity(aid: 'EA', reason: 'x').plainMessage;
    expect(m, allOf(contains('not added'), contains('tampered'), contains('Ask the person')));
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
}
