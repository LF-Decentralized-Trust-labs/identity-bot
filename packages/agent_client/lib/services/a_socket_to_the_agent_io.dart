import 'package:web_socket_channel/io.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

import 'the_owner_at_this_computer.dart';

/// Opens a websocket to [uri], carrying the local owner secret when [uri] is
/// the core on this computer that proved it holds it, and nothing otherwise.
WebSocketChannel connectToTheAgent(Uri uri) =>
    IOWebSocketChannel.connect(uri, headers: headersForSocket(uri));

/// The headers a socket to [uri] carries.
Map<String, String> headersForSocket(Uri uri) => LocalOwnerSecret.headersFor(
    uri.replace(scheme: uri.scheme == 'wss' ? 'https' : 'http'));
