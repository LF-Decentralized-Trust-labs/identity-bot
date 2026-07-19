/// Conditional import router — keeps local_auth off the web build path.
///
/// Web: stub returns unavailable for all methods.
/// Native (desktop + mobile): real local_auth implementation.
export 'local_auth_service_stub.dart'
    if (dart.library.io) 'local_auth_service_native.dart';
