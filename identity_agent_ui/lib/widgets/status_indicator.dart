import 'package:flutter/material.dart';
import '../theme/app_theme.dart';
import '../services/core_service.dart';

class StatusIndicator extends StatelessWidget {
  final CoreConnectionState state;
  final double size;

  const StatusIndicator({
    super.key,
    required this.state,
    this.size = 12,
  });

  Color get _color {
    switch (state) {
      case CoreConnectionState.connected:
        return AppColors.coreActive;
      case CoreConnectionState.connecting:
        return AppColors.corePending;
      case CoreConnectionState.error:
        return AppColors.coreInactive;
      case CoreConnectionState.disconnected:
        return AppColors.textMuted;
    }
  }

  String get label {
    switch (state) {
      case CoreConnectionState.connected:
        return 'ONLINE';
      case CoreConnectionState.connecting:
        return 'CONNECTING';
      case CoreConnectionState.error:
        return 'ERROR';
      case CoreConnectionState.disconnected:
        return 'OFFLINE';
    }
  }

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Container(
          width: size,
          height: size,
          decoration: BoxDecoration(
            color: _color,
            shape: BoxShape.circle,
            boxShadow: [
              BoxShadow(
                color: _color.withOpacity(0.5),
                blurRadius: 8,
                spreadRadius: 1,
              ),
            ],
          ),
        ),
        const SizedBox(width: 8),
        Text(
          label,
          style: TextStyle(
            color: _color,
            fontSize: 11,
            fontWeight: FontWeight.w700,
            letterSpacing: 2.0,
            fontFamily: 'monospace',
          ),
        ),
      ],
    );
  }
}
