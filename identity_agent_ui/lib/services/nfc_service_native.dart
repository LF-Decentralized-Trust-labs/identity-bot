import 'dart:typed_data';
import 'package:nfc_manager/nfc_manager.dart';

/// Handles writing and reading the BIP39 mnemonic to/from an NDEF NFC tag.
///
/// Tag format: plain NDEF text record containing:
///   `identity-agent:seed:<word1> <word2> ... <word12>`
///
/// The prefix allows the app to distinguish identity-agent seed tags from
/// other NDEF tags the user might tap by accident.
class NfcService {
  static const _prefix = 'identity-agent:seed:';

  static Future<bool> isAvailable() => NfcManager.instance.isAvailable();

  /// Starts an NFC write session. Calls [onSuccess] when the write completes
  /// or [onError] with a human-readable message on failure.
  static Future<void> writeSeed(
    List<String> words, {
    void Function()? onSuccess,
    void Function(String error)? onError,
  }) async {
    final text = _prefix + words.join(' ');
    try {
      await NfcManager.instance.startSession(
        alertMessage: 'Hold to an NFC tag to write your seed phrase.',
        onDiscovered: (NfcTag tag) async {
          try {
            final ndef = Ndef.from(tag);
            if (ndef == null) {
              await NfcManager.instance.stopSession(
                  errorMessage: 'Tag does not support NDEF.');
              onError?.call('This NFC tag does not support NDEF format.');
              return;
            }
            if (!ndef.isWritable) {
              await NfcManager.instance.stopSession(
                  errorMessage: 'Tag is read-only.');
              onError?.call('This NFC tag is read-only and cannot be written.');
              return;
            }
            final message = NdefMessage([NdefRecord.createText(text)]);
            await ndef.write(message);
            await NfcManager.instance.stopSession();
            onSuccess?.call();
          } catch (e) {
            await NfcManager.instance.stopSession(
                errorMessage: 'Write failed.');
            onError?.call('Write failed: ${e.toString()}');
          }
        },
      );
    } catch (e) {
      onError?.call('Could not start NFC session: ${e.toString()}');
    }
  }

  /// Starts an NFC read session. Calls [onSuccess] with the parsed word list
  /// if a valid seed tag is found, or [onError] with a message on failure.
  static Future<void> readSeed({
    required void Function(List<String> words) onSuccess,
    void Function(String error)? onError,
  }) async {
    try {
      await NfcManager.instance.startSession(
        alertMessage: 'Hold to your NFC seed tag to verify.',
        onDiscovered: (NfcTag tag) async {
          try {
            final ndef = Ndef.from(tag);
            if (ndef == null) {
              await NfcManager.instance.stopSession(
                  errorMessage: 'Tag not readable.');
              onError?.call('This tag does not contain NDEF data.');
              return;
            }
            final message = ndef.cachedMessage;
            if (message == null || message.records.isEmpty) {
              await NfcManager.instance.stopSession(
                  errorMessage: 'Tag is empty.');
              onError?.call('This NFC tag is empty.');
              return;
            }
            String? found;
            for (final record in message.records) {
              final parsed = _parseTextRecord(record.payload);
              if (parsed != null && parsed.startsWith(_prefix)) {
                found = parsed.substring(_prefix.length);
                break;
              }
            }
            if (found == null) {
              await NfcManager.instance.stopSession(
                  errorMessage: 'Not an identity seed tag.');
              onError?.call(
                  'This tag does not contain an identity seed phrase.');
              return;
            }
            final words = found.trim().split(' ');
            await NfcManager.instance.stopSession();
            onSuccess(words);
          } catch (e) {
            await NfcManager.instance.stopSession(errorMessage: 'Read failed.');
            onError?.call('Read failed: ${e.toString()}');
          }
        },
      );
    } catch (e) {
      onError?.call('Could not start NFC session: ${e.toString()}');
    }
  }

  static Future<void> stopSession() => NfcManager.instance.stopSession();

  // ── OOBI contact-sharing ───────────────────────────────────────────────────

  static const _oobiPrefix = 'identity-agent:oobi:';

  /// Writes an OOBI URL (with optional action param) to a physical NFC tag.
  /// Tag format: NDEF text record containing `identity-agent:oobi:<url>`
  static Future<void> writeOobi(
    String oobiUrl, {
    void Function()? onSuccess,
    void Function(String error)? onError,
  }) async {
    final text = _oobiPrefix + oobiUrl;
    try {
      await NfcManager.instance.startSession(
        alertMessage: 'Hold to an NFC tag to write your identity tap.',
        onDiscovered: (NfcTag tag) async {
          try {
            final ndef = Ndef.from(tag);
            if (ndef == null) {
              await NfcManager.instance.stopSession(errorMessage: 'Tag does not support NDEF.');
              onError?.call('This NFC tag does not support NDEF format.');
              return;
            }
            if (!ndef.isWritable) {
              await NfcManager.instance.stopSession(errorMessage: 'Tag is read-only.');
              onError?.call('This NFC tag is read-only and cannot be written.');
              return;
            }
            final message = NdefMessage([NdefRecord.createText(text)]);
            await ndef.write(message);
            await NfcManager.instance.stopSession();
            onSuccess?.call();
          } catch (e) {
            await NfcManager.instance.stopSession(errorMessage: 'Write failed.');
            onError?.call('Write failed: ${e.toString()}');
          }
        },
      );
    } catch (e) {
      onError?.call('Could not start NFC session: ${e.toString()}');
    }
  }

  /// Starts an NFC read session that listens for identity-agent OOBI tags.
  /// Calls [onSuccess] with the raw OOBI URL (including any ?action= param).
  /// Calls [onError] if the tag is not a valid OOBI tag or on failure.
  /// Does NOT stop the session on success — caller must call [stopSession].
  static Future<void> startOobiReadSession({
    required void Function(String oobiUrl) onSuccess,
    void Function(String error)? onError,
  }) async {
    try {
      await NfcManager.instance.startSession(
        alertMessage: 'Tap an identity tag to add a contact.',
        onDiscovered: (NfcTag tag) async {
          try {
            final ndef = Ndef.from(tag);
            if (ndef == null) {
              onError?.call('This tag does not contain NDEF data.');
              return;
            }
            final message = ndef.cachedMessage;
            if (message == null || message.records.isEmpty) {
              onError?.call('This NFC tag is empty.');
              return;
            }
            for (final record in message.records) {
              final parsed = _parseTextRecord(record.payload);
              if (parsed != null && parsed.startsWith(_oobiPrefix)) {
                final oobiUrl = parsed.substring(_oobiPrefix.length);
                await NfcManager.instance.stopSession();
                onSuccess(oobiUrl);
                return;
              }
            }
            onError?.call('This tag does not contain an identity tap.');
          } catch (e) {
            onError?.call('Read failed: ${e.toString()}');
          }
        },
      );
    } catch (e) {
      onError?.call('Could not start NFC session: ${e.toString()}');
    }
  }

  /// Parses an NDEF text record payload into a plain string.
  /// NDEF text record format (RFC 2396):
  ///   Byte 0: status byte — bit 7 = encoding (0=UTF-8), bits 0-5 = lang code length
  ///   Bytes 1..langLen: ISO 639 language code (e.g. "en")
  ///   Remaining: UTF-8 text
  static String? _parseTextRecord(Uint8List payload) {
    if (payload.isEmpty) return null;
    final langLen = payload[0] & 0x3F;
    if (payload.length <= 1 + langLen) return null;
    return String.fromCharCodes(payload.sublist(1 + langLen));
  }
}
