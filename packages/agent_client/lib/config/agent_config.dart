import 'package:flutter/foundation.dart' show kIsWeb;
import 'platform_helper_stub.dart'
    if (dart.library.io) 'platform_helper_io.dart';

class AgentConfig {
  /// Where the identity's agent is, when it is not on this machine.
  ///
  /// Empty means the ordinary case: this installation holds the identity and
  /// its own core is the agent. Set at startup from what was recorded for the
  /// open profile — never guessed per screen, because a screen that guesses
  /// wrong talks to the local core and gets a plausible answer about nobody.
  ///
  /// Deliberately SEPARATE from [coreBaseUrl] rather than replacing it. Two
  /// different addresses are needed at once in controller mode: identity
  /// requests go to the agent, and the request-signing call goes to the core on
  /// THIS machine, because that is where the enclave key is. Collapsing them
  /// would send the signing call to the agent and nothing would ever be signed.
  static String agentOrigin = '';

  /// Where a request about the identity should go.
  ///
  /// This is what almost every caller wants. [coreBaseUrl] is the core on this
  /// computer, which in controller mode is not the agent and holds no identity.
  static String get agentBaseUrl =>
      agentOrigin.isEmpty ? coreBaseUrl : agentOrigin;

  /// True when this installation is only the front end for an agent elsewhere.
  static bool get isAController => agentOrigin.isNotEmpty;

  static const int defaultDesktopPort = 5050;

  /// The actual port the backend is running on (may differ from default
  /// if port 5050 was occupied and the backend auto-selected a fallback).
  static int desktopPort = defaultDesktopPort;
  static const int mobilePort = 8642;

  static String get coreBaseUrl {
    const envUrl = String.fromEnvironment('CORE_URL', defaultValue: '');
    if (envUrl.isNotEmpty) {
      return envUrl;
    }

    if (kIsWeb) {
      // The API lives beside the page, wherever the page is being served from.
      //
      // Returning '' makes every call root-relative — `/api/identity` — which is
      // correct only when the agent is served at the root of a hostname. An
      // agent served under a path prefix answers at `/{prefix}/api/identity`,
      // and the root-relative call goes somewhere else entirely: on a host that
      // serves several agents under one hostname it reaches no agent at all and
      // returns 404.
      //
      // That 404 is worse than an error, because of how it is read. The app
      // treats "this agent refuses you" (403) as *waiting to be claimed by
      // somebody else*, and anything else as *nothing here yet* — so a 404 sent
      // the person to "Create my identity" on an agent that was already
      // somebody's and would refuse them at the next step. The gate held; the
      // screen was a dead end. Elsewhere the same 404 surfaced raw as
      // "Cannot reach this agent".
      //
      // <base href> does not fix it: the browser applies it to documents and
      // assets, not to a URL a program builds and hands to fetch. So the prefix
      // has to be worked out here.
      //
      // Uri.base is the page's own URL, and with Flutter web's default hash
      // routing the path part stays at whatever the app was served under —
      // routes live after the '#'. An app that switches to path-based routing
      // must revisit this, because then the path carries the route as well.
      final path = Uri.base.path;
      if (path.isEmpty || path == '/') {
        return '';
      }
      return path.endsWith('/') ? path.substring(0, path.length - 1) : path;
    }

    if (isMobilePlatform()) {
      return 'http://127.0.0.1:$mobilePort';
    }

    return 'http://127.0.0.1:$desktopPort';
  }

  static const int healthPollIntervalSeconds = 15;

  /// URL of the public KERI microservice for stateless ACDC operations
  /// (/format-credential, /credential/present, /credential/verify).
  ///
  /// It existed because the mobile KERI engine could not perform them. That
  /// engine is gone — every platform runs the local core — so this is only
  /// still consulted where the local core defers a stateless operation.
  /// Can be overridden at compile-time via the KERI_SERVICE_URL env variable.
  static const String publicKeriServiceUrl = String.fromEnvironment(
    'KERI_SERVICE_URL',
    defaultValue: 'https://keri.grapeid.org',
  );
}
