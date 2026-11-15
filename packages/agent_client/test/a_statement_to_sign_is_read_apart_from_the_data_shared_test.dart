import 'package:agent_client/services/core_service.dart';
import 'package:test/test.dart';

// What the core's decode says for an Ask that asks for a signature (action 6,
// ADR-080): the statement comes as its own part, and the rows of data shared
// stay empty, so a screen cannot file it under what the person is sharing.
void main() {
  test('a statement to sign is read as a statement, not as details', () {
    final r = ScanDecodeResult.fromJson({
      't': 6,
      'action': 'sign_statement',
      'title': 'Sign a statement',
      'counterparty_name': 'https://console.example',
      'statement': {
        'heading': 'Your approval of a decision',
        'form': 'grape-decision-approval/1',
        'rows': [
          {'label': 'Decision 7', 'value': '"Use the queue"'}
        ],
        'verbatim': 'grape-decision-approval/1\ndecision=7',
        'signer_note': 'Only your signature makes https://console.example count this as yours.',
      },
      'ask_digest': 'EDigest',
    });
    expect(r.details, isEmpty);
    expect(r.statement, isNotNull);
    expect(r.statement!.heading, 'Your approval of a decision');
    expect(r.statement!.rows.single.label, 'Decision 7');
    expect(r.statement!.verbatim, 'grape-decision-approval/1\ndecision=7');
    expect(r.statement!.signerNote, contains('Only your signature'));
  });

  test('a request with no statement has none', () {
    expect(ScanDecodeResult.fromJson({'t': 1, 'action': 'login'}).statement, isNull);
  });
}
