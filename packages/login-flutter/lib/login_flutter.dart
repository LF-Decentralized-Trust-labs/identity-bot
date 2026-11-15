/// Sign in with Identity Agent, for an installed front end of a utility app
/// (ADR-072): the screen, the hardware key and the kept grant. What is believed,
/// and how a call is signed and sealed, is `login_dart`'s `AppSession`.
library;

export 'src/hardware_key.dart';
export 'src/secure_grant_store.dart';
export 'src/sign_in_screen.dart';
