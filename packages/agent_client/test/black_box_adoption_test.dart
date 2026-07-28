import 'package:agent_client/services/black_box_adoption.dart';
import 'package:test/test.dart';

Uri page() => Uri.parse('https://grapeid.com/provision');

Uri returnLink({String? state, String box = 'https://abc.agent.grapeid.org', String? code = 'CODE123'}) {
  return Uri.parse('grapeid://adopt').replace(queryParameters: {
    if (state != null) 'state': state,
    'box_url': box,
    if (code != null) 'adoption_code': code,
  });
}

String stateOf(Uri u) => u.queryParameters['state']!;

void main() {
  test('the app completes only a flow it started', () {
    final a = BlackBoxAdoption();
    final started = a.begin(provisioningPage: page());
    final req = a.accept(returnLink(state: stateOf(started)));
    expect(req.boxUrl.host, 'abc.agent.grapeid.org');
    expect(req.adoptionCode, 'CODE123');
  });

  // The attack this exists to stop: an unsolicited link asking this app to
  // adopt somebody else's box, which would make the owner's root delegate to
  // an agent they do not control.
  test('an unsolicited link is refused', () {
    final a = BlackBoxAdoption();
    expect(
      () => a.accept(returnLink(state: 'some-nonce-we-never-issued')),
      throwsA(isA<AdoptionRefused>()),
    );
  });

  test('a link from a different setup is refused', () {
    final a = BlackBoxAdoption();
    a.begin(provisioningPage: page());
    expect(
      () => a.accept(returnLink(state: 'a-different-flow')),
      throwsA(isA<AdoptionRefused>()),
    );
  });

  test('a link with no state at all is refused', () {
    final a = BlackBoxAdoption();
    a.begin(provisioningPage: page());
    expect(() => a.accept(returnLink()), throwsA(isA<AdoptionRefused>()));
  });

  // A screenshotted or shared link must do nothing the second time.
  test('a return can be used once', () {
    final a = BlackBoxAdoption();
    final started = a.begin(provisioningPage: page());
    final link = returnLink(state: stateOf(started));
    a.accept(link);
    expect(() => a.accept(link), throwsA(isA<AdoptionRefused>()));
  });

  test('the adoption code is required', () {
    final a = BlackBoxAdoption();
    final started = a.begin(provisioningPage: page());
    expect(
      () => a.accept(returnLink(state: stateOf(started), code: null)),
      throwsA(isA<AdoptionRefused>()),
    );
  });

  // The adoption code travels in this link. Sending it in the clear would hand
  // it to whoever is listening.
  test('a remote box must be reached over TLS', () {
    final a = BlackBoxAdoption();
    final started = a.begin(provisioningPage: page());
    expect(
      () => a.accept(returnLink(state: stateOf(started), box: 'http://abc.agent.grapeid.org')),
      throwsA(isA<AdoptionRefused>()),
    );
  });

  // Plain HTTP on loopback is how a desktop reaches an agent on its own
  // machine, and there is no network to listen on.
  test('loopback over plain http is allowed', () {
    final a = BlackBoxAdoption();
    final started = a.begin(provisioningPage: page());
    final req = a.accept(returnLink(state: stateOf(started), box: 'http://127.0.0.1:5050'));
    expect(req.boxUrl.port, 5050);
  });

  test('an unreadable box address is refused', () {
    final a = BlackBoxAdoption();
    final started = a.begin(provisioningPage: page());
    expect(
      () => a.accept(returnLink(state: stateOf(started), box: 'not a url')),
      throwsA(isA<AdoptionRefused>()),
    );
  });

  test('two nonces are never the same', () {
    final a = BlackBoxAdoption();
    final seen = <String>{};
    for (var i = 0; i < 20; i++) {
      seen.add(stateOf(a.begin(provisioningPage: page())));
    }
    expect(seen.length, 20);
  });

  test('starting again replaces the pending flow, so a stale page cannot finish', () {
    final a = BlackBoxAdoption();
    final first = a.begin(provisioningPage: page());
    a.begin(provisioningPage: page());
    expect(
      () => a.accept(returnLink(state: stateOf(first))),
      throwsA(isA<AdoptionRefused>()),
    );
  });

  test('cancelling means a later return does nothing', () {
    final a = BlackBoxAdoption();
    final started = a.begin(provisioningPage: page());
    a.cancel();
    expect(a.isPending, isFalse);
    expect(
      () => a.accept(returnLink(state: stateOf(started))),
      throwsA(isA<AdoptionRefused>()),
    );
  });

  test('the refusal reads as something a person can act on', () {
    final a = BlackBoxAdoption();
    try {
      a.accept(returnLink(state: 'x'));
      fail('expected a refusal');
    } on AdoptionRefused catch (e) {
      expect(e.message, contains('did not ask'));
      expect(e.message, isNot(contains('nonce')));
    }
  });
}
