import 'dart:async';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

class SandboxTerminal extends StatefulWidget {
  final String instanceId;
  final String appName;
  final String serverUrl;
  final VoidCallback? onClose;

  const SandboxTerminal({
    super.key,
    required this.instanceId,
    required this.appName,
    required this.serverUrl,
    this.onClose,
  });

  @override
  State<SandboxTerminal> createState() => _SandboxTerminalState();
}

class _SandboxTerminalState extends State<SandboxTerminal> {
  final ScrollController _scrollController = ScrollController();
  final TextEditingController _inputController = TextEditingController();
  final FocusNode _inputFocus = FocusNode();
  final List<TerminalLine> _lines = [];
  WebSocketChannel? _channel;
  bool _connected = false;
  bool _processExited = false;

  @override
  void initState() {
    super.initState();
    _connect();
  }

  @override
  void dispose() {
    _channel?.sink.close();
    _scrollController.dispose();
    _inputController.dispose();
    _inputFocus.dispose();
    super.dispose();
  }

  void _connect() {
    final wsUrl = widget.serverUrl
        .replaceFirst('http://', 'ws://')
        .replaceFirst('https://', 'wss://');
    final uri = Uri.parse('$wsUrl/api/ws/terminal/${widget.instanceId}');

    try {
      _channel = WebSocketChannel.connect(uri);
      setState(() => _connected = true);

      _channel!.stream.listen(
        (data) {
          final text = data.toString();
          if (text == '[Process exited]') {
            setState(() {
              _processExited = true;
              _lines.add(TerminalLine(text: text, isSystem: true));
            });
          } else {
            final isStderr = text.startsWith('[stderr] ');
            final displayText = isStderr
                ? text.substring(9)
                : text.startsWith('[stdout] ')
                    ? text.substring(9)
                    : text;

            setState(() {
              _lines.add(TerminalLine(text: displayText, isStderr: isStderr));
            });
          }
          _scrollToBottom();
        },
        onError: (error) {
          setState(() {
            _connected = false;
            _lines.add(TerminalLine(
              text: 'Connection error: $error',
              isSystem: true,
            ));
          });
        },
        onDone: () {
          setState(() => _connected = false);
        },
      );
    } catch (e) {
      setState(() {
        _connected = false;
        _lines.add(TerminalLine(
          text: 'Failed to connect: $e',
          isSystem: true,
        ));
      });
    }
  }

  void _sendInput(String text) {
    if (_channel != null && _connected && !_processExited) {
      _channel!.sink.add(text);
      setState(() {
        _lines.add(TerminalLine(text: '> $text', isInput: true));
      });
      _inputController.clear();
      _scrollToBottom();
    }
  }

  void _scrollToBottom() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scrollController.hasClients) {
        _scrollController.animateTo(
          _scrollController.position.maxScrollExtent,
          duration: const Duration(milliseconds: 100),
          curve: Curves.easeOut,
        );
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    if (!Platform.isWindows && !Platform.isMacOS && !Platform.isLinux) {
      return const Center(
        child: Text(
          'Terminal display is only available on desktop platforms.',
          style: TextStyle(color: Colors.white70, fontFamily: 'monospace'),
        ),
      );
    }

    return Column(
      children: [
        _buildToolbar(),
        Expanded(child: _buildTerminalOutput()),
        if (!_processExited) _buildInputBar(),
      ],
    );
  }

  Widget _buildToolbar() {
    final statusColor = _processExited
        ? Colors.red
        : _connected
            ? const Color(0xFF00FF41)
            : Colors.amber;
    final statusText = _processExited
        ? 'EXITED'
        : _connected
            ? 'RUNNING'
            : 'DISCONNECTED';

    return Container(
      height: 40,
      padding: const EdgeInsets.symmetric(horizontal: 12),
      decoration: const BoxDecoration(
        color: Color(0xFF1A1A2E),
        border: Border(bottom: BorderSide(color: Color(0xFF16213E))),
      ),
      child: Row(
        children: [
          Container(
            width: 8,
            height: 8,
            decoration: BoxDecoration(
              color: statusColor,
              shape: BoxShape.circle,
            ),
          ),
          const SizedBox(width: 8),
          Text(
            widget.appName,
            style: const TextStyle(
              color: Colors.white,
              fontFamily: 'monospace',
              fontSize: 13,
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(width: 12),
          Text(
            statusText,
            style: TextStyle(
              color: statusColor,
              fontFamily: 'monospace',
              fontSize: 11,
            ),
          ),
          const Spacer(),
          if (!_connected && !_processExited)
            IconButton(
              icon: const Icon(Icons.refresh, color: Colors.white70, size: 18),
              onPressed: () {
                _lines.clear();
                _connect();
              },
              tooltip: 'Reconnect',
              padding: EdgeInsets.zero,
              constraints: const BoxConstraints(minWidth: 32, minHeight: 32),
            ),
          IconButton(
            icon: const Icon(Icons.content_copy, color: Colors.white70, size: 18),
            onPressed: () {
              final text = _lines.map((l) => l.text).join('\n');
              Clipboard.setData(ClipboardData(text: text));
            },
            tooltip: 'Copy output',
            padding: EdgeInsets.zero,
            constraints: const BoxConstraints(minWidth: 32, minHeight: 32),
          ),
          if (widget.onClose != null)
            IconButton(
              icon: const Icon(Icons.close, color: Colors.white70, size: 18),
              onPressed: widget.onClose,
              tooltip: 'Close',
              padding: EdgeInsets.zero,
              constraints: const BoxConstraints(minWidth: 32, minHeight: 32),
            ),
        ],
      ),
    );
  }

  Widget _buildTerminalOutput() {
    return Container(
      color: const Color(0xFF0D0D1A),
      child: ListView.builder(
        controller: _scrollController,
        padding: const EdgeInsets.all(12),
        itemCount: _lines.length,
        itemBuilder: (context, index) {
          final line = _lines[index];
          Color textColor;
          if (line.isSystem) {
            textColor = Colors.amber;
          } else if (line.isStderr) {
            textColor = const Color(0xFFFF6B6B);
          } else if (line.isInput) {
            textColor = const Color(0xFF00D4FF);
          } else {
            textColor = const Color(0xFF00FF41);
          }

          return Padding(
            padding: const EdgeInsets.only(bottom: 2),
            child: SelectableText(
              line.text,
              style: TextStyle(
                color: textColor,
                fontFamily: 'monospace',
                fontSize: 13,
                height: 1.4,
              ),
            ),
          );
        },
      ),
    );
  }

  Widget _buildInputBar() {
    return Container(
      height: 40,
      padding: const EdgeInsets.symmetric(horizontal: 12),
      decoration: const BoxDecoration(
        color: Color(0xFF1A1A2E),
        border: Border(top: BorderSide(color: Color(0xFF16213E))),
      ),
      child: Row(
        children: [
          const Text(
            '> ',
            style: TextStyle(
              color: Color(0xFF00FF41),
              fontFamily: 'monospace',
              fontSize: 13,
            ),
          ),
          Expanded(
            child: TextField(
              controller: _inputController,
              focusNode: _inputFocus,
              style: const TextStyle(
                color: Colors.white,
                fontFamily: 'monospace',
                fontSize: 13,
              ),
              decoration: const InputDecoration(
                border: InputBorder.none,
                isDense: true,
                contentPadding: EdgeInsets.zero,
                hintText: 'Type command...',
                hintStyle: TextStyle(color: Colors.white30),
              ),
              onSubmitted: (text) {
                if (text.isNotEmpty) {
                  _sendInput(text);
                  _inputFocus.requestFocus();
                }
              },
            ),
          ),
          IconButton(
            icon: const Icon(Icons.send, color: Color(0xFF00FF41), size: 16),
            onPressed: () {
              if (_inputController.text.isNotEmpty) {
                _sendInput(_inputController.text);
              }
            },
            padding: EdgeInsets.zero,
            constraints: const BoxConstraints(minWidth: 32, minHeight: 32),
          ),
        ],
      ),
    );
  }
}

class TerminalLine {
  final String text;
  final bool isStderr;
  final bool isSystem;
  final bool isInput;

  TerminalLine({
    required this.text,
    this.isStderr = false,
    this.isSystem = false,
    this.isInput = false,
  });
}
