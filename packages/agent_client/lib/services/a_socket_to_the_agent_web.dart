import 'package:web_socket_channel/web_socket_channel.dart';

/// Opens a websocket to [uri]. A browser sends no secret: a page is never the
/// owner of the core it was served from.
WebSocketChannel connectToTheAgent(Uri uri) => WebSocketChannel.connect(uri);
