import 'package:flutter/material.dart';
import '../../services/recovery_service.dart';
import '../../services/root_seed_handoff.dart';
import '../../theme/app_theme.dart';

enum RecoverySource { localFile, backupOnlyDevice, cloud }

class RecoveryOnboardingScreen extends StatefulWidget {
  final void Function(RecoverySession session) onRecoveryStarted;
  final VoidCallback onBack;

  const RecoveryOnboardingScreen({
    super.key,
    required this.onRecoveryStarted,
    required this.onBack,
  });

  @override
  State<RecoveryOnboardingScreen> createState() =>
      _RecoveryOnboardingScreenState();
}

class _RecoveryOnboardingScreenState extends State<RecoveryOnboardingScreen> {
  final _mnemonicController = TextEditingController();
  final _localPathController = TextEditingController();
  final _identityAidController = TextEditingController();
  final _cloudRefController = TextEditingController();
  final _recoveryService = RecoveryService();

  RecoverySource _source = RecoverySource.localFile;
  String? _archiveB64;
  String? _archiveLabel;
  bool _busy = false;
  String? _error;
  String? _verifyStatus;

  @override
  void dispose() {
    _mnemonicController.dispose();
    _localPathController.dispose();
    _identityAidController.dispose();
    _cloudRefController.dispose();
    super.dispose();
  }

  Future<void> _loadArchive() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      RecoveryRetrieveResult retrieved;
      switch (_source) {
        case RecoverySource.localFile:
          final path = _localPathController.text.trim();
          if (path.isEmpty) throw Exception('Local .iab path required');
          retrieved = await _recoveryService.retrieveFromLocal(path);
          break;
        case RecoverySource.backupOnlyDevice:
          final aid = _identityAidController.text.trim();
          if (aid.isEmpty) throw Exception('Identity AID required');
          retrieved = await _recoveryService.retrieveFromBackupOnly(
            identityAid: aid,
          );
          break;
        case RecoverySource.cloud:
          final ref = _cloudRefController.text.trim();
          if (ref.isEmpty) throw Exception('Cloud reference required');
          retrieved = await _recoveryService.retrieveFromCloud(ref);
          break;
      }
      setState(() {
        _archiveB64 = retrieved.archiveB64;
        _archiveLabel = retrieved.path ?? retrieved.source;
      });
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      setState(() => _busy = false);
    }
  }

  Future<void> _verifyAndStart() async {
    final mnemonic = _mnemonicController.text.trim();
    if (mnemonic.split(RegExp(r'\s+')).length != 24) {
      setState(() => _error = 'Enter all 24 words of your recovery phrase');
      return;
    }
    if (_archiveB64 == null) {
      await _loadArchive();
      if (_archiveB64 == null) return;
    }

    setState(() {
      _busy = true;
      _error = null;
      _verifyStatus = null;
    });
    try {
      final verify = await _recoveryService.verify(
        mnemonic: mnemonic,
        archiveB64: _archiveB64!,
      );
      if (!verify.valid) {
        throw Exception('Archive verification failed');
      }
      setState(() {
        _verifyStatus =
            'Verified ${verify.sectionCount} sections for ${verify.identityAid ?? "identity"}';
      });

      final session = await _recoveryService.start(
        mnemonic: mnemonic,
        archiveB64: _archiveB64!,
      );

      // Reseat the HD root on this device from the verified phrase, so every
      // derived key (pairwise, logins, assets, audit, credential vault)
      // re-derives here — recovery never depends on the old device.
      await RootSeedHandoff.register(mnemonic.split(RegExp(r'\s+')));

      widget.onRecoveryStarted(session);
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.background,
      appBar: AppBar(
        backgroundColor: AppColors.background,
        elevation: 0,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back, color: AppColors.textMuted),
          onPressed: widget.onBack,
        ),
        title: const Text(
          'RECOVER FROM BACKUP',
          style: TextStyle(
            color: AppColors.textPrimary,
            fontSize: 14,
            fontWeight: FontWeight.w700,
            letterSpacing: 1.5,
            fontFamily: 'monospace',
          ),
        ),
      ),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 520),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const Text(
                  'Restore your identity from an encrypted .iab archive. '
                  'You will need your seed phrase. After restore, key rotation is mandatory '
                  'and a cancel window applies before activation.',
                  style: TextStyle(
                    color: AppColors.textSecondary,
                    fontSize: 12,
                    height: 1.6,
                    fontFamily: 'monospace',
                  ),
                ),
                const SizedBox(height: 24),
                const Text(
                  'BACKUP SOURCE',
                  style: TextStyle(
                    color: AppColors.textMuted,
                    fontSize: 11,
                    letterSpacing: 1.2,
                    fontFamily: 'monospace',
                  ),
                ),
                const SizedBox(height: 8),
                SegmentedButton<RecoverySource>(
                  segments: const [
                    ButtonSegment(
                      value: RecoverySource.localFile,
                      label: Text('LOCAL', style: TextStyle(fontFamily: 'monospace', fontSize: 10)),
                    ),
                    ButtonSegment(
                      value: RecoverySource.backupOnlyDevice,
                      label: Text('BACKUP DEVICE', style: TextStyle(fontFamily: 'monospace', fontSize: 10)),
                    ),
                    ButtonSegment(
                      value: RecoverySource.cloud,
                      label: Text('CLOUD', style: TextStyle(fontFamily: 'monospace', fontSize: 10)),
                    ),
                  ],
                  selected: {_source},
                  onSelectionChanged: (s) => setState(() {
                    _source = s.first;
                    _archiveB64 = null;
                    _archiveLabel = null;
                    _error = null;
                  }),
                ),
                const SizedBox(height: 16),
                if (_source == RecoverySource.localFile) ...[
                  TextField(
                    controller: _localPathController,
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                    decoration: const InputDecoration(
                      labelText: 'Path to .iab archive on this device',
                      labelStyle: TextStyle(fontFamily: 'monospace'),
                    ),
                  ),
                  const SizedBox(height: 8),
                  OutlinedButton(
                    onPressed: _busy ? null : _loadArchive,
                    child: const Text('LOAD LOCAL ARCHIVE',
                        style: TextStyle(fontFamily: 'monospace')),
                  ),
                ],
                if (_source == RecoverySource.backupOnlyDevice) ...[
                  TextField(
                    controller: _identityAidController,
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                    decoration: const InputDecoration(
                      labelText: 'Identity AID on backup device',
                      labelStyle: TextStyle(fontFamily: 'monospace'),
                    ),
                  ),
                  const SizedBox(height: 8),
                  OutlinedButton(
                    onPressed: _busy ? null : _loadArchive,
                    child: const Text('FETCH FROM BACKUP DEVICE',
                        style: TextStyle(fontFamily: 'monospace')),
                  ),
                ],
                if (_source == RecoverySource.cloud) ...[
                  TextField(
                    controller: _cloudRefController,
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                    decoration: const InputDecoration(
                      labelText: 'Cloud object reference (stub)',
                      labelStyle: TextStyle(fontFamily: 'monospace'),
                    ),
                  ),
                  const SizedBox(height: 8),
                  OutlinedButton(
                    onPressed: _busy ? null : _loadArchive,
                    child: const Text('FETCH FROM CLOUD',
                        style: TextStyle(fontFamily: 'monospace')),
                  ),
                ],
                const SizedBox(height: 24),
                TextField(
                  controller: _mnemonicController,
                  maxLines: 3,
                  obscureText: true,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                  decoration: const InputDecoration(
                    labelText: 'Seed phrase',
                    labelStyle: TextStyle(fontFamily: 'monospace'),
                    hintText: 'Enter your BIP-39 mnemonic',
                  ),
                ),
                if (_verifyStatus != null) ...[
                  const SizedBox(height: 12),
                  Text(
                    _verifyStatus!,
                    style: const TextStyle(
                      color: AppColors.accent,
                      fontSize: 11,
                      fontFamily: 'monospace',
                    ),
                  ),
                ],
                if (_error != null) ...[
                  const SizedBox(height: 12),
                  Text(
                    _error!,
                    style: const TextStyle(
                      color: Color(0xFFFF6B6B),
                      fontSize: 11,
                      fontFamily: 'monospace',
                    ),
                  ),
                ],
                const SizedBox(height: 24),
                FilledButton(
                  onPressed: _busy ? null : _verifyAndStart,
                  child: _busy
                      ? const SizedBox(
                          width: 18,
                          height: 18,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Text(
                          'VERIFY & START RECOVERY',
                          style: TextStyle(
                            fontFamily: 'monospace',
                            fontWeight: FontWeight.w700,
                            letterSpacing: 1,
                          ),
                        ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}