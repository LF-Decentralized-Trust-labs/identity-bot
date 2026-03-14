import 'dart:async';
import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

class AgentEvent {
  final String type;
  final String timestamp;
  final Map<String, dynamic> payload;

  AgentEvent({
    required this.type,
    required this.timestamp,
    required this.payload,
  });

  factory AgentEvent.fromJson(Map<String, dynamic> json) {
    return AgentEvent(
      type: json['type'] ?? '',
      timestamp: json['timestamp'] ?? '',
      payload: Map<String, dynamic>.from(json['payload'] ?? {}),
    );
  }

  String get senderAid => payload['sender_aid'] ?? '';
  String get senderAlias => payload['sender_alias'] ?? '';
  String get senderPhoto => payload['sender_photo'] ?? '';
  Map<String, dynamic>? get senderJCard =>
      payload['sender_jcard'] is Map<String, dynamic>
          ? payload['sender_jcard'] as Map<String, dynamic>
          : null;
  String get senderDisplayName {
    final jcard = senderJCard;
    if (jcard != null) {
      final fn = jcard['fn'] as String? ?? '';
      if (fn.isNotEmpty) return fn;
    }
    if (senderAlias.isNotEmpty) return senderAlias;
    final aid = senderAid;
    return aid.length > 12 ? '${aid.substring(0, 12)}...' : aid;
  }

  @override
  String toString() => 'AgentEvent(type=$type, alias=$senderAlias, aid=$senderAid)';
}

class EventService {
  static EventService? _instance;

  final String _baseUrl;
  WebSocketChannel? _channel;
  Timer? _reconnectTimer;
  int _reconnectAttempts = 0;
  int _connectionGeneration = 0;
  bool _disposed = false;
  bool _connected = false;

  final _controller = StreamController<AgentEvent>.broadcast();

  Stream<AgentEvent> get events => _controller.stream;
  bool get isConnected => _connected;

  EventService._(this._baseUrl);

  static EventService instance(String baseUrl) {
    if (_instance != null && _instance!._baseUrl == baseUrl) {
      return _instance!;
    }
    _instance?.dispose();
    _instance = EventService._(baseUrl);
    _instance!.connect();
    return _instance!;
  }

  static void reset() {
    _instance?.dispose();
    _instance = null;
  }

  Uri _buildWebSocketUri() {
    if (_baseUrl.isEmpty && kIsWeb) {
      final pageUri = Uri.base;
      final wsScheme = pageUri.scheme == 'https' ? 'wss' : 'ws';
      return Uri.parse('$wsScheme://${pageUri.host}:${pageUri.port}/api/ws/events');
    }

    final wsUrl = _baseUrl
        .replaceFirst('https://', 'wss://')
        .replaceFirst('http://', 'ws://');
    return Uri.parse('$wsUrl/api/ws/events');
  }

  void connect() {
    if (_disposed) return;

    _connectionGeneration++;
    final thisGeneration = _connectionGeneration;
    final uri = _buildWebSocketUri();

    debugPrint('[EventService] *** Connecting to WebSocket: $uri (gen=$thisGeneration)');

    try {
      _channel?.sink.close();
      _channel = WebSocketChannel.connect(uri);

      _channel!.stream.listen(
        (data) {
          if (thisGeneration != _connectionGeneration) return;
          if (!_connected) {
            _connected = true;
            debugPrint('[EventService] *** WebSocket CONNECTED (gen=$thisGeneration)');
          }
          _reconnectAttempts = 0;

          try {
            final json = jsonDecode(data as String);
            final event = AgentEvent.fromJson(json);
            debugPrint('[EventService] *** EVENT RECEIVED: ${event.type} | alias="${event.senderAlias}" | aid=${event.senderAid}');
            _controller.add(event);
            debugPrint('[EventService] *** Event dispatched to ${_controller.hasListener ? "listeners" : "NO listeners"}');
          } catch (e) {
            debugPrint('[EventService] *** Failed to parse event: $e | raw=$data');
          }
        },
        onError: (error) {
          if (thisGeneration != _connectionGeneration) return;
          debugPrint('[EventService] *** WebSocket ERROR: $error (gen=$thisGeneration)');
          _connected = false;
          _scheduleReconnect();
        },
        onDone: () {
          if (thisGeneration != _connectionGeneration) return;
          debugPrint('[EventService] *** WebSocket CLOSED (gen=$thisGeneration)');
          _connected = false;
          _scheduleReconnect();
        },
        cancelOnError: false,
      );
    } catch (e) {
      debugPrint('[EventService] *** Connection FAILED: $e');
      _scheduleReconnect();
    }
  }

  void _scheduleReconnect() {
    if (_disposed) return;
    _reconnectTimer?.cancel();

    final delay = Duration(
      seconds: (_reconnectAttempts < 5)
          ? 2 * (_reconnectAttempts + 1)
          : 30,
    );
    _reconnectAttempts++;

    debugPrint('[EventService] *** Reconnecting in ${delay.inSeconds}s (attempt $_reconnectAttempts)');

    _reconnectTimer = Timer(delay, () {
      if (!_disposed) connect();
    });
  }

  void dispose() {
    debugPrint('[EventService] *** DISPOSING (gen=$_connectionGeneration)');
    _disposed = true;
    _connectionGeneration++;
    _reconnectTimer?.cancel();
    _channel?.sink.close();
    _controller.close();
  }
}
