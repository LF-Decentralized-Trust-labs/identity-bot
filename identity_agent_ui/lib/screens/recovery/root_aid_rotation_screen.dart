import 'package:flutter/material.dart';
import '../../services/recovery_service.dart';
import '../../theme/app_theme.dart';

class RootAidRotationScreen extends StatefulWidget {
  const RootAidRotationScreen({super.key});

  @override
  State<RootAidRotationScreen> createState() => _RootAidRotationScreenState();
}

class _RootAidRotationScreenState extends State<RootAidRotationScreen> {
  final _recoveryService = RecoveryService();
  final _sessionIdController = TextEditingController();
  final _newPubController = TextEditingController();
  final _newNextPubController = TextEditingController();
  final _carryForwardController = TextEditingController();

  RootAidRotationStatus? _status;
  RootAidRotationResult? _lastResult;
  bool _loading = true;
  bool _rotating = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _loadStatus();
  }

  @override
  void dispose() {
    _sessionIdController.dispose();
    _newPubController.dispose();
    _newNextPubController.dispose();
    _carryForwardController.dispose();
    super.dispose();
  }

  Future<void> _loadStatus() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final status = await _recoveryService.rootAidRotationStatus();
      setState(() {
        _status = status;
        _loading = false;
      });
    } catch (e) {
      setState(() {
        _error = e.toString();
        _loading = false;
      });
    }
  }

  Future<void> _rotate() async {
    final sessionId = _sessionIdController.text.trim();
    final newPub = _newPubController.text.trim();
    final newNext = _newNextPubController.text.trim();
    if (sessionId.isEmpty || newPub.isEmpty || newNext.isEmpty) {
      setState(() => _error = 'Session ID and new root keys are required');
      return;
    }

    final carryForward = _carryForwardController.text
        .split(RegExp(r'[,\s]+'))
        .map((s) => s.trim())
        .where((s) => s.isNotEmpty)
        .toList();

    setState(() {
      _rotating = true;
      _error = null;
    });
    try {
      final result = await _recoveryService.rotateRootAid(
        recoverySessionId: sessionId,
        newRootPublicKey: newPub,
        newRootNextPublicKey: newNext,
        carryForwardAids: carryForward,
      );
      setState(() => _lastResult = result);
      await _loadStatus();
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      setState(() => _rotating = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const Center(
        child: CircularProgressIndicator(color: AppColors.accent),
      );
    }

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 640),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Text(
              'BREAK-GLASS ROOT AID ROTATION',
              style: TextStyle(
                color: AppColors.textPrimary,
                fontSize: 14,
                fontWeight: FontWeight.w700,
                letterSpacing: 1.5,
                fontFamily: 'monospace',
              ),
            ),
            const SizedBox(height: 12),
            Text(
              _status?.message ??
                  'Mint a new root AID after recovery. Continuity is proven by anchoring '
                  'the prior KEL tail SAID on the new root KEL via a KERI IXN seal.',
              style: const TextStyle(
                color: AppColors.textSecondary,
                fontSize: 12,
                height: 1.6,
                fontFamily: 'monospace',
              ),
            ),
            if (_status != null) ...[
              const SizedBox(height: 16),
              _infoRow('Available', _status!.available ? 'YES' : 'NO'),
              if (_status!.rotationCount != null)
                _infoRow('Prior rotations', '${_status!.rotationCount}'),
              if (_status!.currentRootAid != null)
                _infoRow('Current root', _status!.currentRootAid!),
            ],
            const SizedBox(height: 24),
            TextField(
              controller: _sessionIdController,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              decoration: const InputDecoration(
                labelText: 'Recovery session ID',
                labelStyle: TextStyle(fontFamily: 'monospace'),
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _newPubController,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              decoration: const InputDecoration(
                labelText: 'New root public key (CESR qb64)',
                labelStyle: TextStyle(fontFamily: 'monospace'),
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _newNextPubController,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              decoration: const InputDecoration(
                labelText: 'New root next public key (CESR qb64)',
                labelStyle: TextStyle(fontFamily: 'monospace'),
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _carryForwardController,
              maxLines: 2,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              decoration: const InputDecoration(
                labelText: 'Carry-forward AIDs (comma-separated pairwise/contact AIDs)',
                labelStyle: TextStyle(fontFamily: 'monospace'),
                hintText: 'EPairwise1, EPairwise2',
              ),
            ),
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
            if (_lastResult != null) ...[
              const SizedBox(height: 16),
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: AppColors.accent.withOpacity(0.08),
                  border: Border.all(color: AppColors.accent.withOpacity(0.3)),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Rotation ${_lastResult!.status}',
                      style: const TextStyle(
                        color: AppColors.accent,
                        fontFamily: 'monospace',
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                    const SizedBox(height: 8),
                    _infoRow('Old root', _lastResult!.oldRootAid),
                    _infoRow('New root', _lastResult!.newRootAid),
                    _infoRow('Anchor IXN', _lastResult!.anchorIxnSaid),
                    _infoRow('Notified', '${_lastResult!.notificationsSent} parties'),
                  ],
                ),
              ),
            ],
            const SizedBox(height: 24),
            FilledButton(
              onPressed: (_rotating || !(_status?.available ?? false)) ? null : _rotate,
              child: _rotating
                  ? const SizedBox(
                      width: 18,
                      height: 18,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Text(
                      'ROTATE ROOT AID',
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
    );
  }

  Widget _infoRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 4),
      child: Text(
        '$label: $value',
        style: const TextStyle(
          color: AppColors.textMuted,
          fontSize: 11,
          fontFamily: 'monospace',
        ),
      ),
    );
  }
}