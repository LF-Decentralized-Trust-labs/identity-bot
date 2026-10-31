/// Whether [a] and [b] hold the same values, compared without leaking where
/// they first differ: every position is looked at whatever the earlier ones
/// held. Lengths are not secret and are compared first.
///
/// The one copy. Four files each wrote this loop for themselves, and copies
/// of a security check drift apart.
bool constantTimeEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}
