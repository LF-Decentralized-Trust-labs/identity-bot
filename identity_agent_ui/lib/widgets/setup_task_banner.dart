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
    final color = _done == 0 ? const Color(0xFFCC3333) : const Color(0xFFCC8800);
    return _HoverBanner(
      color: color,
      pct: pct,
      done: _done,
      remaining: remaining,
      onTap: _openChecklist,
      onDismiss: _dismiss,
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

// ── Hover-animated desktop banner ─────────────────────────────────────────────

class _HoverBanner extends StatefulWidget {
  final Color color;
  final double pct;
  final int done;
  final int remaining;
  final VoidCallback onTap;
  final VoidCallback onDismiss;

  const _HoverBanner({
    required this.color,
    required this.pct,
    required this.done,
    required this.remaining,
    required this.onTap,
    required this.onDismiss,
  });

  @override
  State<_HoverBanner> createState() => _HoverBannerState();
}

class _HoverBannerState extends State<_HoverBanner> {
  bool _hovered = false;

  @override
  Widget build(BuildContext context) {
    final c = widget.color;
    return MouseRegion(
      cursor: SystemMouseCursors.click,
      onEnter: (_) => setState(() => _hovered = true),
      onExit: (_) => setState(() => _hovered = false),
      child: GestureDetector(
        onTap: widget.onTap,
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 150),
          margin: const EdgeInsets.only(top: 12),
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 11),
          decoration: BoxDecoration(
            color: c.withOpacity(_hovered ? 0.16 : 0.08),
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: c.withOpacity(_hovered ? 0.55 : 0.35)),
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
                      value: widget.pct,
                      strokeWidth: 3,
                      backgroundColor: c.withOpacity(0.15),
                      color: c,
                    ),
                    Text(
                      '${widget.done}',
                      style: TextStyle(
                        color: c,
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
                    style: TextStyle(fontSize: 13, color: c, height: 1.3),
                    children: [
                      TextSpan(
                        text: '${widget.remaining} task${widget.remaining == 1 ? '' : 's'} remaining',
                        style: const TextStyle(fontWeight: FontWeight.w700),
                      ),
                      const TextSpan(
                          text: '  ·  Click to complete setup and unlock all features.'),
                    ],
                  ),
                ),
              ),
              IconButton(
                icon: const Icon(Icons.close, size: 14),
                color: c.withOpacity(0.6),
                onPressed: widget.onDismiss,
                padding: EdgeInsets.zero,
                constraints: const BoxConstraints(minWidth: 28, minHeight: 28),
                tooltip: 'Dismiss',
              ),
            ],
          ),
        ),
      ),
    );
  }
}
