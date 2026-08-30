/// The software this app is willing to adopt a sealed machine for.
///
/// A machine that proves what it launched has said what it is. It has not said
/// whether the owner accepts it, and those are different questions — an agent
/// with no policy refuses every sealed machine on purpose, because a missing
/// policy read as "accept anything" would make every other check decorative.
///
/// THIS IS A BOOTSTRAP COPY, AND IT IS NOT THE ANSWER. The decided design is a
/// signed list, published, with the publisher's key pinned in the app, so that
/// everybody receives the same list and serving one person a different one
/// requires the key and is detectable. Two properties this cannot offer:
///
///   - nothing here is signed, so a build carries whatever it was compiled with
///   - every image rebuild changes the measurement, so this goes stale and an
///     app that ships it alone would reject boxes until people update
///
/// It exists because the alternative today is an app that cannot adopt anything
/// at all, and because the signed design names a bootstrap copy as part of
/// itself. When the list is published this becomes its seed and stops being
/// consulted on its own.
library;

/// Measurements compiled into this build, newline or comma separated.
///
/// Supplied at build time rather than hard-coded, because which software is
/// acceptable belongs to whoever ships the app, and differs for a deployment
/// running its own sealed hardware.
const String _fromBuild = String.fromEnvironment('ACCEPTED_MEASUREMENTS');

/// What this build will accept, as lowercase hex, empty when nothing was set.
///
/// Empty is a real answer and the safe one: it adopts nothing rather than
/// anything, and the agent says so in words somebody can act on.
List<String> acceptedMeasurements() {
  final raw = _fromBuild.trim();
  if (raw.isEmpty) return const [];
  return raw
      .split(RegExp(r'[\s,]+'))
      .map((m) => m.trim().toLowerCase())
      .where((m) => RegExp(r'^[0-9a-f]{96}$').hasMatch(m))
      .toList(growable: false);
}
