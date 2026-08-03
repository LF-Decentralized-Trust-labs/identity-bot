import 'package:http/http.dart' as http;

/// Carrying a browser session on every request, without having to remember to.
///
/// A browser holds no key and should not be given one, so it cannot sign the
/// way an app does. What it can hold is a session the owner granted from a
/// device that does hold the key. This attaches that session to each request at
/// the transport, for the same reason OwnerSigningClient signs there: a call
/// added tomorrow works without anybody remembering to add a header.
///
/// LIKE THE SIGNING CLIENT, IT IS SCOPED TO ONE ORIGIN. The same client resolves
/// other people's discovery records and talks to relays and witnesses; sending
/// a session token to those would hand a stranger the thing that authorises
/// you. Compared on scheme, host and port rather than by prefix, because
/// `https://my-agent.example.com.attacker.test` starts with the agent's origin
/// and is not the agent.
///
/// The token is held in memory only. Sessions do not survive the agent
/// restarting — deliberately, on that side — so persisting one here would mean
/// holding a credential that is already dead, and turning a clean sign-in into
/// a confusing "signed in but refused".
class BrowserSessionClient extends http.BaseClient {
  BrowserSessionClient({required this.agentOrigin, http.Client? inner})
      : _inner = inner ?? http.Client();

  /// The origin this session belongs to, as scheme://host:port. Requests
  /// anywhere else pass through untouched.
  final String agentOrigin;

  final http.Client _inner;
  String? _token;

  String? get token => _token;
  bool get hasSession => _token != null;

  /// Start carrying a session, once the browser has claimed one.
  void adopt(String token) => _token = token;

  /// Stop carrying it — on sign-out, or when the agent says it is no longer
  /// valid. Clearing on rejection matters: a client that keeps presenting a
  /// dead token turns "your session ended" into "everything is broken".
  void discard() => _token = null;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final token = _token;
    if (token == null || !_isOwnAgent(request.url)) {
      return _inner.send(request);
    }
    // Never overwrite an Authorization header a caller set deliberately: that
    // is how a request meant to present something else presents the session.
    if (request.headers.containsKey('Authorization')) {
      return _inner.send(request);
    }
    request.headers['Authorization'] = 'Bearer $token';
    final response = await _inner.send(request);
    // A session that expired or was revoked is dead everywhere, not just here.
    // Dropping it means the next call presents nothing and gets a clean "sign
    // in" rather than a second confusing refusal.
    if (response.statusCode == 401) _token = null;
    return response;
  }

  bool _isOwnAgent(Uri url) {
    // An empty origin means same-origin, which is exactly the web case: the app
    // was served BY the agent, so AgentConfig gives it no base URL and every
    // request is relative. Treating that as "not my agent" would attach the
    // session to nothing and leave the browser permanently signed out while
    // holding a perfectly good token.
    if (agentOrigin.isEmpty) return !url.hasAuthority;

    final own = Uri.tryParse(agentOrigin);
    if (own == null || own.host.isEmpty) return false;
    return url.scheme == own.scheme &&
        url.host == own.host &&
        url.port == own.port;
  }

  @override
  void close() {
    _inner.close();
    super.close();
  }
}
