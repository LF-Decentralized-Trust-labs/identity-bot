/// The rule for a public name, as the core states it (relayproto.ValidName):
/// a pattern, a sequence that may not appear, and the length limits. A screen
/// applies this rather than keeping its own copy, so it refuses a name the
/// relay would refuse and never a name the relay would take.
class PublicNameRule {
  PublicNameRule({
    required String pattern,
    required this.forbids,
    required this.minLength,
    required this.maxLength,
    required this.text,
  }) : _pattern = RegExp(pattern);

  /// Reads the `public_name_rule` the core returns with the reachability
  /// settings. Throws a [FormatException] if the core did not send one (an
  /// older core), so a caller can fall back knowingly.
  factory PublicNameRule.fromJson(Object? json) {
    if (json is! Map ||
        json['pattern'] is! String ||
        json['forbids'] is! String ||
        json['min_length'] is! int ||
        json['max_length'] is! int ||
        json['text'] is! String) {
      throw const FormatException('the core did not state a public name rule');
    }
    return PublicNameRule(
      pattern: json['pattern'] as String,
      forbids: json['forbids'] as String,
      minLength: json['min_length'] as int,
      maxLength: json['max_length'] as int,
      text: json['text'] as String,
    );
  }

  final RegExp _pattern;

  /// A sequence no name may contain (two hyphens).
  final String forbids;
  final int minLength;
  final int maxLength;

  /// The rule in plain words, for telling a person why a name was refused.
  final String text;

  /// Whether [name] is a public name the relay accepts.
  bool isValid(String name) =>
      _pattern.hasMatch(name) && (forbids.isEmpty || !name.contains(forbids));
}
