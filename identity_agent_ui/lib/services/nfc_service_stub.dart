/// Web / desktop stub — NFC hardware is not available on these platforms.
class NfcService {
  static Future<bool> isAvailable() async => false;

  static Future<void> writeSeed(
    List<String> words, {
    void Function()? onSuccess,
    void Function(String error)? onError,
  }) async {
    onError?.call('NFC is not available on this platform.');
  }

  static Future<void> readSeed({
    required void Function(List<String> words) onSuccess,
    void Function(String error)? onError,
  }) async {
    onError?.call('NFC is not available on this platform.');
  }

  static Future<void> stopSession() async {}

  static Future<void> writeOobi(
    String oobiUrl, {
    void Function()? onSuccess,
    void Function(String error)? onError,
  }) async {
    onError?.call('NFC is not available on this platform.');
  }

  static Future<void> startOobiReadSession({
    required void Function(String oobiUrl) onSuccess,
    void Function(String error)? onError,
  }) async {
    onError?.call('NFC is not available on this platform.');
  }
}
