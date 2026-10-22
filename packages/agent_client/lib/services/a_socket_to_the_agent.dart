/// Opening a websocket to an Identity Agent, carrying what proves this app.
///
/// A websocket is a request like any other, and a socket to the core on this
/// computer needs the local owner secret like any other request does. A
/// browser cannot set headers on a socket and proves itself another way, so
/// only the native implementation adds it.
export 'a_socket_to_the_agent_web.dart'
    if (dart.library.io) 'a_socket_to_the_agent_io.dart';
