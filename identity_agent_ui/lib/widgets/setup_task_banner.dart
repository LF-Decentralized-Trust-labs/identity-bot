import 'package:flutter/material.dart';
import 'package:agent_client/services/setup_task_service.dart';
import '../services/preferences_service.dart';
import 'package:agent_client/services/keri_service.dart';
import '../screens/setup_checklist_screen.dart';

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
  bool _autoOpened = false;
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
    final tasks = SetupTaskService.orderedTasks(needsRemoteBrain: needsRemoteBrain, includeSecureKeyStorage: false);
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
      // Auto-open checklist on first dashboard visit after onboarding
      if (!_autoOpened && done < tasks.length) {
        _autoOpened = true;
        WidgetsBinding.instance.addPostFrameCallback((_) {
          if (mounted) _openChecklist();
        });
      }
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

    return widget.isMobile
        ? _buildMobileBanner(remaining)
        : _buildDesktopBanner(remaining);
  }

  Widget _buildDesktopBanner(int remaining) {
    return _HoverBanner(
      color: const Color(0xFFCC8800),
      remaining: remaining,
      onTap: _openChecklist,
      onDismiss: _dismiss,
    );
  }

  Widget _buildMobileBanner(int remaining) {
    const color = Color(0xFFCC8800);
    return GestureDetector(
      onTap: _openChecklist,
      child: Container(
        margin: const EdgeInsets.fromLTRB(16, 8, 16, 0),
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
        decoration: BoxDecoration(
          color: color.withOpacity(0.08),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: color.withOpacity(0.3)),
        ),
        child: Row(
          children: [
            Icon(Icons.shield_outlined, size: 20, color: color),
            const SizedBox(width: 10),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    '$remaining more ${remaining == 1 ? 'step' : 'steps'} to complete setup',
                    style: const TextStyle(
                      color: Color(0xFF161616),
                      fontSize: 13,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const Text(
                    'Required to continue using your Identity Agent.',
                    style: TextStyle(
                      color: Color(0xFF8D8D8D),
                      fontSize: 11,
                    ),
                  ),
                ],
              ),
            ),
            Icon(Icons.chevron_right, color: color, size: 18),
          ],
        ),
      ),
    );
  }

  Future<void> _openChecklist() async {
    if (widget.isMobile) {
      await showModalBottomSheet<void>(
        context: context,
        isScrollControlled: true,
        backgroundColor: Colors.transparent,
        builder: (_) => DraggableScrollableSheet(
          initialChildSize: 0.9,
          maxChildSize: 0.95,
          expand: false,
          builder: (_, ctrl) => ClipRRect(
            borderRadius:
                const BorderRadius.vertical(top: Radius.circular(20)),
            child: SetupChecklistScreen(
              onDone: () => Navigator.of(context).pop(),
              keriService: widget.keriService,
              serverUrl: widget.serverUrl,
              hostingChoice: _hostingChoice,
              remoteBrainUrl: _remoteBrainUrl,
            ),
          ),
        ),
      );
    } else {
      await showDialog<void>(
        context: context,
        barrierDismissible: true,
        builder: (ctx) => Dialog(
          backgroundColor: Colors.transparent,
          insetPadding:
              const EdgeInsets.symmetric(horizontal: 64, vertical: 48),
          child: ClipRRect(
            borderRadius: BorderRadius.circular(16),
            child: ConstrainedBox(
              constraints:
                  const BoxConstraints(maxWidth: 560, maxHeight: 680),
              child: SetupChecklistScreen(
                onDone: () => Navigator.of(ctx).pop(),
                keriService: widget.keriService,
                serverUrl: widget.serverUrl,
                hostingChoice: _hostingChoice,
                remoteBrainUrl: _remoteBrainUrl,
              ),
            ),
          ),
        ),
      );
    }
    _load();
  }
}

// ── Hover-animated desktop banner ─────────────────────────────────────────────

class _HoverBanner extends StatefulWidget {
  final Color color;
  final int remaining;
  final VoidCallback onTap;
  final VoidCallback onDismiss;

  const _HoverBanner({
    required this.color,
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
              Icon(Icons.shield_outlined, size: 16, color: c),
              const SizedBox(width: 10),
              Expanded(
                child: RichText(
                  text: TextSpan(
                    style: TextStyle(fontSize: 13, color: c, height: 1.3),
                    children: [
                      TextSpan(
                        text: '${widget.remaining} more ${widget.remaining == 1 ? 'step' : 'steps'} to complete setup',
                        style: const TextStyle(fontWeight: FontWeight.w700),
                      ),
                      const TextSpan(text: '  ·  Required to continue using your Identity Agent.'),
                    ],
                  ),
                ),
              ),
              const SizedBox(width: 8),
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
