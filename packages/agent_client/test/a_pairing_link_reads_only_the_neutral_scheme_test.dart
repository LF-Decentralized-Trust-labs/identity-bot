import 'package:agent_client/services/pairing_invitation.dart';
import 'package:test/test.dart';

void main() {
  test('a link built here round-trips back through the parser', () {
    final raw = PairingInvitation.link(
      host: 'https://box.example.test',
      code: 'ABC123',
    );
    expect(raw, startsWith('identity-agent://pair?'));

    final it = PairingInvitation.parse(raw);
    expect(it, isNotNull);
    expect(it!.host, 'https://box.example.test');
    expect(it.code, 'ABC123');
    expect(it.kind, 'individual');
    expect(it.isOrganisation, isFalse);
    expect(it.ownerAid, isEmpty);
    expect(it.reportTo, isEmpty);
  });

  test('the old vendor scheme no longer reads — the whole point of the change',
      () {
    // Before the neutral cutover this parsed. It must not now: the core reads
    // one scheme, and it is not a vendor's.
    final it = PairingInvitation.parse(
        'grapeid://pair?host=https://box.example.test&code=ABC123');
    expect(it, isNull);
  });

  test('anything that is not our scheme is not one of ours', () {
    for (final raw in [
      'https://box.example.test/pair?code=ABC123',
      'other://pair?host=https://box.example.test&code=ABC123',
      'not a link at all',
    ]) {
      expect(PairingInvitation.parse(raw), isNull, reason: raw);
    }
  });

  test('our scheme but the wrong verb is refused', () {
    // Right scheme, wrong host — a rental link, not a pairing one.
    expect(
      PairingInvitation.parse(
          'identity-agent://rent?host=https://box.example.test&code=ABC123'),
      isNull,
    );
  });

  test('a host and a code are both required', () {
    expect(PairingInvitation.parse('identity-agent://pair?code=ABC123'), isNull);
    expect(
      PairingInvitation.parse(
          'identity-agent://pair?host=https://box.example.test'),
      isNull,
    );
  });

  test('an organisation ask parses and is flagged as one', () {
    final raw = PairingInvitation.link(
      host: 'https://box.example.test',
      code: 'ABC123',
      kind: 'organisation',
    );
    final it = PairingInvitation.parse(raw);
    expect(it, isNotNull);
    expect(it!.kind, 'organisation');
    expect(it.isOrganisation, isTrue);
  });

  test('an ask nobody recognises is refused, not treated as a computer', () {
    expect(
      PairingInvitation.parse(
          'identity-agent://pair?host=https://box.example.test&code=ABC123&kind=something'),
      isNull,
    );
  });

  test('a host that is not an address is refused', () {
    expect(
      PairingInvitation.parse(
          'identity-agent://pair?host=not-an-address&code=ABC123'),
      isNull,
    );
  });

  test('an owner and a report address are carried when present', () {
    final raw = PairingInvitation.link(
      host: 'https://box.example.test',
      code: 'ABC123',
      kind: 'organisation',
      ownerAid: 'EOwnerPairwise',
      reportTo: 'https://relay.example.test/report',
    );
    final it = PairingInvitation.parse(raw);
    expect(it, isNotNull);
    expect(it!.ownerAid, 'EOwnerPairwise');
    expect(it.reportTo, 'https://relay.example.test/report');
  });

  test('an unusable report address is dropped, but the invitation survives', () {
    // Failing to report back costs an identifier on somebody else's screen;
    // refusing here would cost them the organisation. So drop the address, keep
    // the ask.
    final it = PairingInvitation.parse(
        'identity-agent://pair?host=https://box.example.test&code=ABC123&report=garbage');
    expect(it, isNotNull);
    expect(it!.reportTo, isEmpty);
  });
}
