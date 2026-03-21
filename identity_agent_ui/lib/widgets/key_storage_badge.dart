import 'package:flutter/material.dart';
import '../services/enclave_service.dart';
import '../services/core_service.dart';

/// Small inline badge showing hardware key-backing status.
/// Renders nothing until the first detection completes.
class KeyStorageBadge extends StatefulWidget {
  /// Desktop: pass the app's CoreService so the badge can query the Go backend.
  /// Mobile: omit — EnclaveService answers locally without a network call.
  final CoreService? coreService;

  const KeyStorageBadge({super.key, this.coreService});

  @override
  State<KeyStorageBadge> createState() => _KeyStorageBadgeState();
}

class _KeyStorageBadgeState extends State<KeyStorageBadge> {
  EnclaveStatusResponse? _status;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final status =
        await EnclaveService(coreService: widget.coreService).detect();
    if (mounted) setState(() => _status = status);
  }

  @override
  Widget build(BuildContext context) {
    final s = _status;
    if (s == null) return const SizedBox.shrink();

    final Color color;
    final IconData icon;
    final String label;

    if (s.hardwareBacked) {
      // Genuine hardware enclave (TPM 2.0, Apple Secure Enclave, Android Keystore).
      color = const Color(0xFF4CAF50);
      icon = Icons.shield;
      label = s.backingLabel;
    } else if (s.tpmPresent == true) {
      // TPM chip detected but not enabled in firmware — actionable by user.
      color = const Color(0xFFFFB74D);
      icon = Icons.shield_outlined;
      label = 'Software (TPM disabled)';
    } else {
      // No hardware enclave available on this device.
      color = const Color(0xFF78909C);
      icon = Icons.shield_outlined;
      label = 'Software storage';
    }

    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(icon, color: color, size: 12),
        const SizedBox(width: 4),
        Text(
          'Keys: $label',
          style: TextStyle(
            color: color,
            fontSize: 10,
            fontFamily: 'monospace',
          ),
        ),
      ],
    );
  }
}
