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

  void connect() {
    if (_disposed) return;

    _connectionGeneration++;
    final thisGeneration = _connectionGeneration;

    final wsUrl = _baseUrl
        .replaceFirst('https://', 'wss://')
        .replaceFirst('http://', 'ws://');
    final uri = Uri.parse('$wsUrl/api/ws/events');

    debugPrint('[EventService] Connecting to $uri (gen=$thisGeneration)');

    try {
      _channel?.sink.close();
      _channel = WebSocketChannel.connect(uri);

      _channel!.stream.listen(
        (data) {
          if (thisGeneration != _connectionGeneration) return;
          _connected = true;
          _reconnectAttempts = 0;

          try {
            final json = jsonDecode(data as String);
            final event = AgentEvent.fromJson(json);
            debugPrint('[EventService] Event received: ${event.type}');
            _controller.add(event);
          } catch (e) {
            debugPrint('[EventService] Failed to parse event: $e');
          }
        },
        onError: (error) {
          if (thisGeneration != _connectionGeneration) return;
          debugPrint('[EventService] WebSocket error: $error');
          _connected = false;
          _scheduleReconnect();
        },
        onDone: () {
          if (thisGeneration != _connectionGeneration) return;
          debugPrint('[EventService] WebSocket closed');
          _connected = false;
          _scheduleReconnect();
        },
        cancelOnError: false,
      );
    } catch (e) {
      debugPrint('[EventService] Connection failed: $e');
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

    debugPrint('[EventService] Reconnecting in ${delay.inSeconds}s (attempt $_reconnectAttempts)');

    _reconnectTimer = Timer(delay, () {
      if (!_disposed) connect();
    });
  }

  void dispose() {
    _disposed = true;
    _connectionGeneration++;
    _reconnectTimer?.cancel();
    _channel?.sink.close();
    _controller.close();
  }
}
