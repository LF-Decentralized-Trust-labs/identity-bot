/// What somebody typed or pasted, as the origin an Identity Agent is reached at.
///
/// ONE PLACE, for both apps. It decides two things.
///
/// First, tidying: a person pastes what they were given, and what they were
/// given has a trailing slash from a browser, or no scheme at all because
/// nobody types one. Neither is a mistake on their part. The address is
/// REBUILT FROM ITS PARTS, so nothing depends on an expression matching (the
/// one this replaced matched a literal dollar sign, did nothing, and looked
/// right in a diff for weeks). A trailing slash, a query and a fragment go; a
/// path is refused (see below).
///
/// Second, and this is the security rule: **https, except for this computer.**
/// Nothing the agent answers is secret to a person on the path unless the
/// connection is encrypted, and the approval of this computer and everything
/// shown afterwards travels over it. The proof that an agent holds its keys
/// (an_agent_proving_itself.dart) is not tied to the connection that follows
/// it, so only TLS stops somebody in the middle from relaying the proof and
/// then altering what comes after. An address on a local network is NOT an
/// exception: that is where a person in the middle is easiest. The one
/// exception is the computer itself (`localhost`, `127.x`, `::1`), where nobody
/// is in the middle and development and tests run.
class AnAgentAddress {
  const AnAgentAddress._();

  /// Whether [host] is this computer.
  static bool isThisComputer(String host) {
    final h = host.toLowerCase();
    return h == 'localhost' ||
        h == '::1' ||
        h == '[::1]' ||
        _isA127Address(h);
  }

  static bool _isA127Address(String h) {
    final parts = h.split('.');
    if (parts.length != 4 || parts.first != '127') return false;
    return parts.every((p) {
      final n = int.tryParse(p);
      return n != null && n >= 0 && n <= 255 && p == '$n';
    });
  }

  /// The origin for [typed], or throws [ThatIsNotAnAddress] with words for the
  /// person.
  static String asAnOrigin(String typed) {
    var text = typed.trim();
    if (text.isEmpty) {
      throw const ThatIsNotAnAddress('Enter the address of the server.');
    }
    if (!text.contains('://')) {
      final bare = Uri.tryParse('https://$text');
      final local = bare != null && isThisComputer(bare.host);
      text = '${local ? 'http' : 'https'}://$text';
    }
    final parsed = Uri.tryParse(text);
    if (parsed == null ||
        parsed.host.isEmpty ||
        (parsed.scheme != 'http' && parsed.scheme != 'https') ||
        parsed.userInfo.isNotEmpty) {
      throw const ThatIsNotAnAddress(
          'That does not look like an address. It should look like '
          'https://agent.example.com');
    }
    if (parsed.scheme == 'http' && !isThisComputer(parsed.host)) {
      throw const ThatIsNotAnAddress(
          'That address is not encrypted. Use the one that starts with '
          'https://, so nobody between this computer and the server can read '
          'or change what is sent.');
    }
    // NO PATH. The proof is made for an origin (scheme, host, port) and an agent
    // proves itself at the root of it, so an address with a path would prove
    // whatever is at the root and then talk to something else under the path,
    // which on a shared host is somebody else's. An agent is reached at its own
    // origin.
    if (parsed.path.replaceAll('/', '').isNotEmpty) {
      throw const ThatIsNotAnAddress(
          'Use the address of the server itself, with nothing after it. It '
          'should look like https://agent.example.com');
    }
    return Uri(
      scheme: parsed.scheme,
      host: parsed.host,
      port: parsed.hasPort ? parsed.port : null,
    ).toString();
  }
}

/// What was typed is not an address this app will connect to. [words] is for the
/// screen.
class ThatIsNotAnAddress implements Exception {
  const ThatIsNotAnAddress(this.words);
  final String words;
  @override
  String toString() => words;
}
