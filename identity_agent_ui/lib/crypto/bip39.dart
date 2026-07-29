import 'dart:math';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:pointycastle/export.dart';
import 'wordlist.dart';

class Bip39 {
  /// Generates a recovery phrase.
  ///
  /// 256 bits, so 24 words. The phrase is not a password on the identity — it
  /// IS the identity, and it is the only thing that survives every device
  /// being lost, so its strength is the ceiling on everything else.
  ///
  /// Callers should not pass a weaker strength. The parameter remains only
  /// because the entropy-to-words conversion below is general.
  static List<String> generateMnemonic({int strength = 256}) {
    final random = Random.secure();
    final entropy = Uint8List(strength ~/ 8);
    for (int i = 0; i < entropy.length; i++) {
      entropy[i] = random.nextInt(256);
    }
    return _entropyToMnemonic(entropy);
  }

  static List<String> _entropyToMnemonic(Uint8List entropy) {
    final hash = sha256.convert(entropy);
    final checksumBits = hash.bytes[0];

    final bits = StringBuffer();
    for (final byte in entropy) {
      bits.write(byte.toRadixString(2).padLeft(8, '0'));
    }

    final checksumLength = entropy.length ~/ 4;
    final checksumStr = checksumBits.toRadixString(2).padLeft(8, '0');
    bits.write(checksumStr.substring(0, checksumLength));

    final bitString = bits.toString();
    final wordCount = bitString.length ~/ 11;

    final words = <String>[];
    for (int i = 0; i < wordCount; i++) {
      final segment = bitString.substring(i * 11, (i + 1) * 11);
      final index = int.parse(segment, radix: 2);
      words.add(bip39EnglishWords[index]);
    }

    return words;
  }

  static Uint8List mnemonicToSeed(List<String> mnemonic, {String passphrase = ''}) {
    final mnemonicStr = mnemonic.join(' ');
    final salt = 'mnemonic$passphrase';

    final pbkdf2 = PBKDF2KeyDerivator(HMac(SHA512Digest(), 128));
    pbkdf2.init(Pbkdf2Parameters(
      Uint8List.fromList(salt.codeUnits),
      2048,
      64,
    ));

    return pbkdf2.process(Uint8List.fromList(mnemonicStr.codeUnits));
  }

  static bool validateMnemonic(List<String> words) {
    // 24 words only. Twelve was never issued to anybody — it was an unnoticed
    // default rather than a decision — so accepting it here would widen what a
    // restore trusts without a single real phrase to justify it.
    if (words.length != 24) return false;
    for (final word in words) {
      if (!bip39EnglishWords.contains(word.toLowerCase())) return false;
    }
    return true;
  }
}
