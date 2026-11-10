import 'package:agent_client/services/an_agent_address.dart';
import 'package:test/test.dart';

/// What somebody types becomes an address the app will connect to, and an
/// address that is not encrypted is refused unless it is this computer.
void main() {
  String ok(String typed) => AnAgentAddress.asAnOrigin(typed);

  test('a bare name becomes https', () {
    expect(ok('agent.example.com'), 'https://agent.example.com');
  });

  test('a trailing slash and a query go', () {
    expect(ok('https://agent.example.com/'), 'https://agent.example.com');
    expect(ok('https://agent.example.com/?x=1#y'), 'https://agent.example.com');
  });

  test('a path is refused: the proof is made for the origin, not for a prefix',
      () {
    expect(() => ok('https://shared-host.example/~somebody'),
        throwsA(isA<ThatIsNotAnAddress>()));
  });

  test('an address that only looks like this computer is not it', () {
    expect(() => ok('http://127.999.1.1:5151'),
        throwsA(isA<ThatIsNotAnAddress>()));
  });

  test('a port is kept', () {
    expect(ok('https://agent.example.com:8443'),
        'https://agent.example.com:8443');
  });

  group('plain http', () {
    test('is accepted for this computer only', () {
      expect(ok('http://127.0.0.1:5151'), 'http://127.0.0.1:5151');
      expect(ok('http://localhost:5151'), 'http://localhost:5151');
      expect(ok('127.0.0.1:5151'), 'http://127.0.0.1:5151');
      expect(ok('localhost:5151'), 'http://localhost:5151');
    });

    test('is refused on a local network, where somebody in the middle is easiest',
        () {
      for (final typed in [
        'http://192.168.1.20:5151',
        'http://10.0.0.5',
        'http://agent.example.com',
      ]) {
        expect(() => ok(typed), throwsA(isA<ThatIsNotAnAddress>()),
            reason: typed);
      }
    });

    test('a bare address on a local network becomes https, not http', () {
      expect(ok('192.168.1.20:5151'), 'https://192.168.1.20:5151');
      expect(ok('10.0.0.5'), 'https://10.0.0.5');
    });

    test('a host that only begins like this computer is not this computer', () {
      expect(() => ok('http://127.0.0.1.evil.example'),
          throwsA(isA<ThatIsNotAnAddress>()));
      expect(() => ok('http://localhost.evil.example'),
          throwsA(isA<ThatIsNotAnAddress>()));
    });
  });

  test('nothing, or something that is not an address, is refused in words', () {
    for (final typed in ['', '   ', 'ftp://x.example.com', 'https://user@x.example.com']) {
      expect(() => ok(typed), throwsA(isA<ThatIsNotAnAddress>()),
          reason: typed);
    }
  });
}
