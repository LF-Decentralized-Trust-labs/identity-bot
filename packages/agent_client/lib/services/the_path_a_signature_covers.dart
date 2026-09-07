/// The path a signed request to an agent must be SIGNED over.
///
/// A machine signature covers the request's path — never the host, because the
/// same agent is reached by different names and a signature over the host would
/// break the moment a relay renamed it. What the original design missed is that
/// a PATH-MOUNTING relay renames the path too: several agents live under one
/// host, told apart by a leading path token (`/cl6uodq…`), and the relay strips
/// that token before the agent sees the request. So the agent routes and
/// verifies on `/api/…`, while the request URL built here still carries the
/// token. Signing the token-carrying path produces a signature over a string
/// the agent never rebuilds, and it refuses every one — which is exactly what an
/// owner or controller saw as a 403 on every write to a relayed box.
///
/// So the prefix the agent is mounted under is removed, leaving precisely the
/// path the agent receives and verifies. When the agent is reached at a bare
/// origin — no relay, no prefix — there is nothing to remove and the path is
/// returned unchanged, so this is correct for a self-hosted box as well as a
/// relayed one.
///
/// [agentOrigin] is the agent's full public origin including any mount prefix
/// (e.g. `https://agent.example/cl6uodq…`); [requestUrl] is the URL the request
/// is actually sent to. Only the path is returned, always beginning with `/`.
String pathSignatureCovers(String agentOrigin, Uri requestUrl) {
  // The mount prefix, with any trailing slash removed so it is a clean prefix
  // to strip: `/cl6uodq…` rather than `/cl6uodq…/`.
  final prefix =
      (Uri.tryParse(agentOrigin)?.path ?? '').replaceAll(RegExp(r'/+$'), '');
  final path = requestUrl.path;
  // No prefix to strip — a bare origin. The path is already what the agent sees.
  if (prefix.isEmpty || prefix == '/') return path;
  // The prefix itself, reached with no further path.
  if (path == prefix) return '/';
  // Under the prefix: strip it, keeping the leading slash of what remains.
  if (path.startsWith('$prefix/')) return path.substring(prefix.length);
  // Not under the prefix at all — nothing to strip, so sign what is there. This
  // is the safe direction: a mismatch fails closed at the agent rather than
  // silently signing a path the caller did not send.
  return path;
}
