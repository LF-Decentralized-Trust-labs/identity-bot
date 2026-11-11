// A stand-in for a core an earlier run left behind: answers /api/health and
// proves it holds the secret kept in its data directory, writes .port and
// .pid beside it, and goes on until it is signalled. Run by a test as a
// separate process, so ending it is the real thing.
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

Future<void> main(List<String> args) async {
  final dir = args.first;
  final secret = File('$dir/local-owner-secret').readAsStringSync().trim();
  final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  File('$dir/.port').writeAsStringSync('${server.port}');
  File('$dir/.pid').writeAsStringSync('$pid');
  ProcessSignal.sigterm.watch().listen((_) {
    exit(0);
  });
  await for (final req in server) {
    if (req.uri.path == '/api/local-owner/proof') {
      final nonce = req.uri.queryParameters['nonce'] ?? '';
      final mac = Hmac(sha256, utf8.encode(secret)).convert(utf8.encode(
          'identity-agent local owner proof\n${server.port}\n$nonce'));
      req.response.write(jsonEncode(
          {'proof': base64Url.encode(mac.bytes).replaceAll('=', '')}));
    } else {
      req.response.write('{"ok":true}');
    }
    await req.response.close();
  }
}
