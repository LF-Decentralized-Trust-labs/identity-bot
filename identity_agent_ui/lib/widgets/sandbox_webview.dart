// Conditional import: use the real InAppWebView on desktop (dart:io available),
// fall back to a stub on web to avoid importing native-only types.
export 'sandbox_webview_stub.dart'
    if (dart.library.io) 'sandbox_webview_native.dart';
