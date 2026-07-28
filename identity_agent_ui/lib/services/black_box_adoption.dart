import 'dart:convert';
import 'dart:math';

/// Renting an agent, from the app's side.
///
/// The app does not provision and does not take payment — that happens on the
/// web, which is a decision with a reason: no payment UI in the app avoids the
/// store cut and keeps card handling out of the client entirely.
///
/// So the app's job is narrower and entirely about safety. It sends the person
/// to a page, and then decides whether to believe what comes back. That
/// decision is the whole of this file.
///
/// The attack it exists to stop: a link that arrives unsolicited and asks this
/// app to adopt somebody else's box. Adopting means the owner's root issues a
/// delegation — so a person who taps the wrong link would give an agent they do
/// not control the ability to speak as their delegate. Not root compromise, but
/// close enough to matter.
///
/// The defence is that the app only completes a flow it started. It mints a
/// nonce before opening the page, and refuses any return that does not carry
/// exactly that nonce back.
class BlackBoxAdoption {
  BlackBoxAdoption({Random? random}) : _random = random ?? Random.secure();

  final Random _random;

  /// The flow the app is currently waiting on, if any. One at a time: a second
  /// request replaces the first, so a stale page cannot complete later.
  String? _pendingNonce;

  /// Whether a flow is in progress.
  bool get isPending => _pendingNonce != null;

  /// Starts a provisioning flow and returns the URL to open.
  ///
  /// The nonce is generated here and remembered here. It is the only thing that
  /// makes the return trustworthy, so it is never taken from a caller.
  Uri begin({required Uri provisioningPage}) {
    final nonce = _newNonce();
    _pendingNonce = nonce;
    return provisioningPage.replace(queryParameters: {
      ...provisioningPage.queryParameters,
      'state': nonce,
    });
  }

  /// Reads a deep link or scanned QR and returns what to adopt.
  ///
  /// Throws [AdoptionRefused] rather than returning null, because every reason
  /// to refuse is something the person should be told, and a null would let a
  /// caller carry on with nothing.
  AdoptionRequest accept(Uri returned) {
    final pending = _pendingNonce;
    if (pending == null) {
      throw const AdoptionRefused(
        'This app did not ask to add an agent. If you were setting one up, '
        'start again from the app rather than from the link.',
      );
    }

    final state = returned.queryParameters['state'];
    if (state == null || state.isEmpty) {
      throw const AdoptionRefused(
        'That link is missing the code proving it belongs to the setup you '
        'started.',
      );
    }
    if (!_constantTimeEquals(state, pending)) {
      throw const AdoptionRefused(
        'That link belongs to a different setup than the one you started. '
        'It was not opened.',
      );
    }

    final boxUrl = returned.queryParameters['box_url'];
    final adoptionCode = returned.queryParameters['adoption_code'];
    if (boxUrl == null || boxUrl.isEmpty) {
      throw const AdoptionRefused('That link does not say which agent to add.');
    }
    if (adoptionCode == null || adoptionCode.isEmpty) {
      throw const AdoptionRefused(
        'That link is missing the one-time code that proves this agent was '
        'set up for you.',
      );
    }

    final parsed = Uri.tryParse(boxUrl);
    if (parsed == null || !parsed.hasScheme || parsed.host.isEmpty) {
      throw const AdoptionRefused('That link points at an address we cannot read.');
    }
    // Plain HTTP is allowed only for loopback, which is how a desktop reaches
    // an agent on the same machine. Anything else on the network must be TLS:
    // an adoption carries a one-time code, and sending it in the clear would
    // hand it to whoever is listening.
    final isLoopback = parsed.host == 'localhost' ||
        parsed.host == '127.0.0.1' ||
        parsed.host == '::1';
    if (parsed.scheme != 'https' && !isLoopback) {
      throw const AdoptionRefused(
        'That agent would be contacted over an unencrypted connection.',
      );
    }

    // Spent. A return can be used once — a link that is screenshotted, shared
    // or reopened does nothing the second time.
    _pendingNonce = null;

    return AdoptionRequest(boxUrl: parsed, adoptionCode: adoptionCode);
  }

  /// Abandons the pending flow, for a person who backs out.
  void cancel() => _pendingNonce = null;

  String _newNonce() {
    final bytes = List<int>.generate(32, (_) => _random.nextInt(256));
    return base64Url.encode(bytes).replaceAll('=', '');
  }

  /// Compares without leaking where two values first differ. The nonce is not
  /// a secret an attacker is guessing character by character, but comparing it
  /// in variable time is a habit worth not having.
  static bool _constantTimeEquals(String a, String b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a.codeUnitAt(i) ^ b.codeUnitAt(i);
    }
    return diff == 0;
  }
}

/// What the app is being asked to adopt, once the return has been believed.
class AdoptionRequest {
  const AdoptionRequest({required this.boxUrl, required this.adoptionCode});

  final Uri boxUrl;
  final String adoptionCode;

  /// What the confirmation screen shows. The person is about to have their
  /// root sign a delegation, so they see where it is going in plain terms
  /// before that happens — the checks above stop the attacks we thought of.
  String get displayHost => boxUrl.host;
}

/// A refusal, with the reason written for the person rather than for a log.
class AdoptionRefused implements Exception {
  const AdoptionRefused(this.message);
  final String message;

  @override
  String toString() => message;
}
