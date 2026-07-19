import 'package:flutter/material.dart';
import '../../theme/mobile_theme.dart';
import 'package:agent_client/services/nfc_service.dart';
import 'package:agent_client/services/secure_key_store.dart';
import 'package:agent_client/services/setup_task_service.dart';

enum NfcSeedMode { write, verify }

enum _ScanState { idle, scanning, success, error }

class MobileNfcSeedScreen extends StatefulWidget {
  final NfcSeedMode mode;

  const MobileNfcSeedScreen({super.key, required this.mode});

  @override
  State<MobileNfcSeedScreen> createState() => _MobileNfcSeedScreenState();
}

class _MobileNfcSeedScreenState extends State<MobileNfcSeedScreen>
    with SingleTickerProviderStateMixin {
  _ScanState _state = _ScanState.idle;
  String? _errorMessage;
  String? _resultMessage;
  bool _nfcAvailable = false;
  List<String>? _mnemonic;
  late AnimationController _pulseController;

  @override
  void initState() {
    super.initState();
    _pulseController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1200),
    )..repeat(reverse: true);
    _init();
  }

  @override
  void dispose() {
    _pulseController.dispose();
    // Best-effort stop any active NFC session
    NfcService.stopSession();
    super.dispose();
  }

  Future<void> _init() async {
    final available = await NfcService.isAvailable();
    if (widget.mode == NfcSeedMode.write) {
      final mnemonic = await SecureKeyStore.loadMnemonic();
      setState(() {
        _nfcAvailable = available;
        _mnemonic = mnemonic;
      });
    } else {
      setState(() => _nfcAvailable = available);
    }
  }

  Future<void> _start() async {
    if (!_nfcAvailable) return;
    setState(() {
      _state = _ScanState.scanning;
      _errorMessage = null;
      _resultMessage = null;
    });

    if (widget.mode == NfcSeedMode.write) {
      final words = _mnemonic;
      if (words == null) {
        setState(() {
          _state = _ScanState.error;
          _errorMessage = 'No seed phrase found. Complete setup first.';
        });
        return;
      }
      await NfcService.writeSeed(
        words,
        onSuccess: () async {
          await SetupTaskService.markComplete(SetupTask.backupSeedPhrase);
          if (mounted) {
            setState(() {
              _state = _ScanState.success;
              _resultMessage =
                  'Seed phrase written successfully!\nStore this tag somewhere safe.';
            });
          }
        },
        onError: (err) {
          if (mounted) {
            setState(() {
              _state = _ScanState.error;
              _errorMessage = err;
            });
          }
        },
      );
    } else {
      // Verify mode
      final stored = await SecureKeyStore.loadMnemonic();
      await NfcService.readSeed(
        onSuccess: (words) {
          if (!mounted) return;
          if (stored == null) {
            setState(() {
              _state = _ScanState.error;
              _errorMessage =
                  'No stored seed phrase to compare against.';
            });
            return;
          }
          final match = words.length == stored.length &&
              List.generate(words.length, (i) => words[i] == stored[i])
                  .every((b) => b);
          setState(() {
            _state = match ? _ScanState.success : _ScanState.error;
            _resultMessage = match
                ? 'Seed phrase verified! Your NFC tag matches perfectly.'
                : 'Mismatch — the words on this tag do not match your stored seed phrase.';
            _errorMessage = match ? null : _resultMessage;
            if (match) _resultMessage = _resultMessage;
          });
        },
        onError: (err) {
          if (mounted) {
            setState(() {
              _state = _ScanState.error;
              _errorMessage = err;
            });
          }
        },
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final isWrite = widget.mode == NfcSeedMode.write;

    return Scaffold(
      backgroundColor: MobileColors.background,
      appBar: AppBar(
        backgroundColor: MobileColors.surface,
        foregroundColor: MobileColors.textPrimary,
        title: Text(
          isWrite ? 'Write Seed to NFC Tag' : 'Verify NFC Seed Tag',
          style: const TextStyle(
            fontSize: 17,
            fontWeight: FontWeight.w600,
          ),
        ),
        elevation: 0,
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              const SizedBox(height: 24),
              _buildStateIcon(),
              const SizedBox(height: 32),
              _buildTitle(isWrite),
              const SizedBox(height: 12),
              _buildSubtitle(isWrite),
              const Spacer(),
              if (isWrite && _mnemonic != null && _state == _ScanState.idle)
                _buildWordPreview(),
              if (isWrite && _mnemonic != null && _state == _ScanState.idle)
                const SizedBox(height: 24),
              _buildActionButton(isWrite),
              const SizedBox(height: 12),
              if (_state == _ScanState.success && isWrite)
                TextButton(
                  onPressed: () {
                    // Go to verify after a successful write
                    Navigator.of(context).pushReplacement(MaterialPageRoute(
                      builder: (_) => const MobileNfcSeedScreen(
                          mode: NfcSeedMode.verify),
                    ));
                  },
                  child: const Text(
                    'Verify the tag now →',
                    style: TextStyle(color: MobileColors.primary),
                  ),
                ),
              if (_state == _ScanState.error || _state == _ScanState.success)
                TextButton(
                  onPressed: () {
                    setState(() {
                      _state = _ScanState.idle;
                      _errorMessage = null;
                      _resultMessage = null;
                    });
                  },
                  child: const Text('Try again',
                      style: TextStyle(color: MobileColors.textSecondary)),
                ),
              const SizedBox(height: 12),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildStateIcon() {
    switch (_state) {
      case _ScanState.idle:
        return AnimatedBuilder(
          animation: _pulseController,
          builder: (_, __) => Container(
            width: 120,
            height: 120,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: MobileColors.primary
                  .withOpacity(0.08 + _pulseController.value * 0.06),
              border: Border.all(
                color: MobileColors.primary
                    .withOpacity(0.3 + _pulseController.value * 0.2),
                width: 2,
              ),
            ),
            child: const Icon(Icons.nfc, size: 56, color: MobileColors.primary),
          ),
        );
      case _ScanState.scanning:
        return AnimatedBuilder(
          animation: _pulseController,
          builder: (_, __) => Container(
            width: 120,
            height: 120,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: Colors.blue.withOpacity(0.1 + _pulseController.value * 0.08),
              border: Border.all(
                color: Colors.blue.withOpacity(0.5 + _pulseController.value * 0.3),
                width: 2,
              ),
            ),
            child: const Icon(Icons.sensors, size: 56, color: Colors.blue),
          ),
        );
      case _ScanState.success:
        return Container(
          width: 120,
          height: 120,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: Colors.green.withOpacity(0.1),
            border: Border.all(color: Colors.green.withOpacity(0.5), width: 2),
          ),
          child: const Icon(Icons.check_circle_outline,
              size: 56, color: Colors.green),
        );
      case _ScanState.error:
        return Container(
          width: 120,
          height: 120,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: MobileColors.error.withOpacity(0.1),
            border:
                Border.all(color: MobileColors.error.withOpacity(0.5), width: 2),
          ),
          child: Icon(Icons.error_outline, size: 56, color: MobileColors.error),
        );
    }
  }

  Widget _buildTitle(bool isWrite) {
    String text;
    switch (_state) {
      case _ScanState.idle:
        text = isWrite ? 'Ready to write' : 'Ready to verify';
      case _ScanState.scanning:
        text = 'Scanning…';
      case _ScanState.success:
        text = isWrite ? 'Write successful' : 'Verified';
      case _ScanState.error:
        text = 'Something went wrong';
    }
    return Text(
      text,
      style: const TextStyle(
        color: MobileColors.textPrimary,
        fontSize: 22,
        fontWeight: FontWeight.w700,
      ),
      textAlign: TextAlign.center,
    );
  }

  Widget _buildSubtitle(bool isWrite) {
    if (_state == _ScanState.error && _errorMessage != null) {
      return Text(
        _errorMessage!,
        style: TextStyle(color: MobileColors.error, fontSize: 14, height: 1.5),
        textAlign: TextAlign.center,
      );
    }
    if (_state == _ScanState.success && _resultMessage != null) {
      return Text(
        _resultMessage!,
        style: const TextStyle(
            color: Colors.green, fontSize: 14, height: 1.5),
        textAlign: TextAlign.center,
      );
    }
    if (!_nfcAvailable) {
      return const Text(
        'NFC is not available on this device or is turned off.\nEnable NFC in Settings and try again.',
        style: TextStyle(
            color: MobileColors.textSecondary, fontSize: 14, height: 1.5),
        textAlign: TextAlign.center,
      );
    }

    final String body;
    if (_state == _ScanState.scanning) {
      body = isWrite
          ? 'Hold the back of your phone firmly against the NFC tag until you feel a vibration.'
          : 'Hold the back of your phone against the NFC tag you wrote your seed to.';
    } else {
      body = isWrite
          ? 'Your 12-word seed phrase will be written to the tag. '
              'Anyone with physical access to the tag can read your words — store it securely.'
          : 'Place your phone against the NFC seed tag. '
              'The app will compare the words on the tag to your stored seed phrase.';
    }
    return Text(
      body,
      style: const TextStyle(
          color: MobileColors.textSecondary, fontSize: 14, height: 1.5),
      textAlign: TextAlign.center,
    );
  }

  Widget _buildWordPreview() {
    final words = _mnemonic!;
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: MobileColors.surfaceSecondary,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: MobileColors.border),
      ),
      child: Wrap(
        spacing: 8,
        runSpacing: 8,
        children: [
          for (int i = 0; i < words.length; i++)
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
              decoration: BoxDecoration(
                color: MobileColors.surface,
                borderRadius: BorderRadius.circular(6),
                border: Border.all(color: MobileColors.border),
              ),
              child: Text(
                '${i + 1}. ${words[i]}',
                style: const TextStyle(
                  color: MobileColors.textPrimary,
                  fontSize: 12,
                  fontFamily: 'monospace',
                ),
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildActionButton(bool isWrite) {
    if (_state == _ScanState.scanning) {
      return SizedBox(
        width: double.infinity,
        child: OutlinedButton(
          onPressed: () {
            NfcService.stopSession();
            setState(() => _state = _ScanState.idle);
          },
          style: OutlinedButton.styleFrom(
            foregroundColor: MobileColors.textSecondary,
            side: const BorderSide(color: MobileColors.border),
            padding: const EdgeInsets.symmetric(vertical: 16),
            shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12)),
          ),
          child: const Text('Cancel'),
        ),
      );
    }
    if (_state == _ScanState.success) {
      return SizedBox(
        width: double.infinity,
        child: ElevatedButton(
          onPressed: () => Navigator.of(context).pop(true),
          style: ElevatedButton.styleFrom(
            backgroundColor: Colors.green,
            foregroundColor: Colors.white,
            padding: const EdgeInsets.symmetric(vertical: 16),
            shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12)),
          ),
          child: const Text('Done'),
        ),
      );
    }
    return SizedBox(
      width: double.infinity,
      child: ElevatedButton.icon(
        onPressed: _nfcAvailable ? _start : null,
        icon: Icon(isWrite ? Icons.nfc : Icons.search, size: 20),
        label: Text(isWrite ? 'Start NFC Write' : 'Start NFC Verify'),
        style: ElevatedButton.styleFrom(
          backgroundColor: MobileColors.primary,
          foregroundColor: MobileColors.textOnPrimary,
          disabledBackgroundColor: MobileColors.border,
          padding: const EdgeInsets.symmetric(vertical: 16),
          shape:
              RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        ),
      ),
    );
  }
}
