import 'dart:math';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:pointycastle/export.dart';
import 'wordlist.dart';

class Bip39 {
  static List<String> generateMnemonic({int strength = 128}) {
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
    if (words.length != 12 && words.length != 24) return false;
    for (final word in words) {
      if (!bip39EnglishWords.contains(word.toLowerCase())) return false;
    }
    return true;
  }
}
