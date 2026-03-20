import 'package:flutter/material.dart';
import '../services/setup_task_service.dart';
import '../services/preferences_service.dart';
import '../services/keri_service.dart';
import '../screens/setup_checklist_screen.dart';
import '../screens/mobile/mobile_setup_checklist_screen.dart';

/// Persistent banner shown at the top of the dashboard while setup tasks remain
/// incomplete. Self-dismissible. Loads [HostingChoice] from [PreferencesService].
class SetupTaskBanner extends StatefulWidget {
  final bool isMobile;
  final KeriService keriService;
  final String? serverUrl;

  const SetupTaskBanner({
    super.key,
    required this.isMobile,
    required this.keriService,
    this.serverUrl,
  });

  @override
  State<SetupTaskBanner> createState() => _SetupTaskBannerState();
}

class _SetupTaskBannerState extends State<SetupTaskBanner> {
  int _done = 0;
  int _total = 0;
  bool _dismissed = false;
  bool _loaded = false;
  HostingChoice? _hostingChoice;
  String? _remoteBrainUrl;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final dismissed = await SetupTaskService.isChecklistDismissed();
    if (dismissed) {
      if (mounted) setState(() { _dismissed = true; _loaded = true; });
      return;
    }

    final hosting = await PreferencesService.getHostingChoice();
    final remoteBrain = await PreferencesService.getRemoteBrainUrl();
    final needsRemoteBrain = hosting == HostingChoice.keysHereBrainLater;
    final tasks = SetupTaskService.orderedTasks(needsRemoteBrain: needsRemoteBrain);
    final state = await SetupTaskService.loadState(tasks);
    final done = state.values.where((v) => v).length;

    if (mounted) {
      setState(() {
        _hostingChoice = hosting;
        _remoteBrainUrl = remoteBrain;
        _done = done;
        _total = tasks.length;
        _loaded = true;
      });
    }
  }

  Future<void> _dismiss() async {
    await SetupTaskService.dismissChecklist();
    if (mounted) setState(() => _dismissed = true);
  }

  @override
  Widget build(BuildContext context) {
    if (!_loaded || _dismissed || (_done >= _total && _total > 0)) {
      return const SizedBox.shrink();
    }

    final remaining = _total - _done;
    final pct = _total == 0 ? 0.0 : _done / _total;

    return widget.isMobile
        ? _buildMobileBanner(remaining, pct)
        : _buildDesktopBanner(remaining, pct);
  }

  Widget _buildDesktopBanner(int remaining, double pct) {
    return GestureDetector(
      onTap: _openChecklist,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 10),
        decoration: const BoxDecoration(
          color: Color(0xFF1A1A2E),
          border: Border(
            bottom: BorderSide(color: Color(0xFF2D2D4E), width: 1),
          ),
        ),
        child: Row(
          children: [
            SizedBox(
              width: 28,
              height: 28,
              child: Stack(
                alignment: Alignment.center,
                children: [
                  CircularProgressIndicator(
                    value: pct,
                    strokeWidth: 3,
                    backgroundColor: const Color(0xFF2D2D4E),
                    color: const Color(0xFF00CC66),
                  ),
                  Text(
                    '$_done',
                    style: const TextStyle(
                      color: Color(0xFFE0E0E0),
                      fontSize: 9,
                      fontWeight: FontWeight.w700,
                      fontFamily: 'monospace',
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: RichText(
                text: TextSpan(
                  style: const TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 12,
                    height: 1.3,
                  ),
                  children: [
                    const TextSpan(
                      text: 'Setup incomplete — ',
                      style: TextStyle(color: Color(0xFFB0B0B0)),
                    ),
                    TextSpan(
                      text:
                          '$remaining task${remaining == 1 ? '' : 's'} remaining.',
                      style: const TextStyle(
                        color: Color(0xFFE0E0E0),
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const TextSpan(
                      text: '  Tap to continue.',
                      style: TextStyle(color: Color(0xFF4488FF)),
                    ),
                  ],
                ),
              ),
            ),
            IconButton(
              icon: const Icon(Icons.close, size: 16),
              color: const Color(0xFF606060),
              onPressed: _dismiss,
              padding: EdgeInsets.zero,
              constraints: const BoxConstraints(minWidth: 28, minHeight: 28),
              tooltip: 'Dismiss',
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildMobileBanner(int remaining, double pct) {
    return GestureDetector(
      onTap: _openChecklist,
      child: Container(
        margin: const EdgeInsets.fromLTRB(16, 8, 16, 0),
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
        decoration: BoxDecoration(
          color: const Color(0xFF4589FF).withOpacity(0.06),
          borderRadius: BorderRadius.circular(12),
          border:
              Border.all(color: const Color(0xFF4589FF).withOpacity(0.2)),
        ),
        child: Row(
          children: [
            SizedBox(
              width: 32,
              height: 32,
              child: Stack(
                alignment: Alignment.center,
                children: [
                  CircularProgressIndicator(
                    value: pct,
                    strokeWidth: 3,
                    backgroundColor: const Color(0xFFE0E0E0),
                    color: pct == 1.0
                        ? const Color(0xFF24A148)
                        : const Color(0xFF4589FF),
                  ),
                  Text(
                    '$_done',
                    style: const TextStyle(
                      color: Color(0xFF161616),
                      fontSize: 9,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    'Finish setting up your identity',
                    style: TextStyle(
                      color: Color(0xFF161616),
                      fontSize: 13,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  Text(
                    '$remaining task${remaining == 1 ? '' : 's'} remaining',
                    style: const TextStyle(
                      color: Color(0xFF8D8D8D),
                      fontSize: 11,
                    ),
                  ),
                ],
              ),
            ),
            const Icon(Icons.chevron_right,
                color: Color(0xFF4589FF), size: 18),
          ],
        ),
      ),
    );
  }

  Future<void> _openChecklist() async {
    await Navigator.of(context).push(MaterialPageRoute(
      builder: (_) => widget.isMobile
          ? MobileSetupChecklistScreen(
              onDone: () => Navigator.of(context).pop(),
              keriService: widget.keriService,
              serverUrl: widget.serverUrl,
              hostingChoice: _hostingChoice,
              remoteBrainUrl: _remoteBrainUrl,
            )
          : SetupChecklistScreen(
              onDone: () => Navigator.of(context).pop(),
              keriService: widget.keriService,
              serverUrl: widget.serverUrl,
              hostingChoice: _hostingChoice,
              remoteBrainUrl: _remoteBrainUrl,
            ),
    ));
    _load();
  }
}
