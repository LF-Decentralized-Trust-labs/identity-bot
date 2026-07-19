// Conditional export: native (iOS/Android) implementation on dart:io platforms,
// stub on web. See CLAUDE.md § "Flutter Web Compatibility: Conditional Imports".
export 'nfc_service_stub.dart'
    if (dart.library.io) 'nfc_service_native.dart';
