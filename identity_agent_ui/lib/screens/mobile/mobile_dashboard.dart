import 'dart:async';
import 'package:flutter/material.dart';
import '../../theme/mobile_theme.dart';
import '../../services/core_service.dart';
import '../../config/agent_config.dart';
import '../../widgets/identity_card.dart';
import '../../widgets/alert_card.dart';
import '../../widgets/task_card.dart';
import '../../widgets/activity_entry.dart';
import '../../models/background_task.dart';
import '../../models/activity_log_entry.dart';

class MobileDashboard extends StatefulWidget {
  final String? serverUrl;
  final VoidCallback onMenuTap;

  const MobileDashboard({
    super.key,
    this.serverUrl,
    required this.onMenuTap,
  });

  @override
  State<MobileDashboard> createState() => _MobileDashboardState();
}

class _MobileDashboardState extends State<MobileDashboard> with SingleTickerProviderStateMixin {
  late final CoreService _coreService;
  late final TabController _tabController;
  Timer? _pollTimer;

  String _displayName = '';
  String _agentUrl = '';
  String? _photoBase64;
  List<ContactResponse> _alertContacts = [];
  List<PendingRequestResponse> _pendingRequests = [];
  int _alertCount = 0;
  bool _loading = true;

  Set<String> _knownAlertAids = {};
  OverlayEntry? _popupOverlay;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 3, vsync: this);
    _coreService = CoreService(baseUrl: widget.serverUrl ?? AgentConfig.coreBaseUrl);
    _loadData();
    _pollTimer = Timer.periodic(const Duration(seconds: 15), (_) => _pollAlerts());
  }

  @override
  void dispose() {
    _pollTimer?.cancel();
    _tabController.dispose();
    _coreService.dispose();
    _dismissPopup();
    super.dispose();
  }

  Future<void> _loadData() async {
    await Future.wait([_loadProfile(), _loadEndpoint(), _loadAlerts(isInitial: true)]);
    if (mounted) setState(() => _loading = false);
  }

  Future<void> _loadProfile() async {
    try {
      final profile = await _coreService.getProfile();
      if (mounted) {
        setState(() {
          _displayName = profile.fullName;
          _photoBase64 = profile.photo.isNotEmpty ? profile.photo : null;
        });
      }
    } catch (e) {
      debugPrint('[MobileDashboard] Profile load error: $e');
    }
  }

  Future<void> _loadEndpoint() async {
    try {
      final endpoint = await _coreService.getEndpoint();
      if (mounted) {
        setState(() {
          _agentUrl = (endpoint['url'] as String?) ?? '';
        });
      }
    } catch (e) {
      debugPrint('[MobileDashboard] Endpoint load error: $e');
    }
  }

  Future<void> _loadAlerts({bool isInitial = false}) async {
    try {
      final alerts = await _coreService.getAlerts();
      if (mounted) {
        setState(() {
          _alertContacts = alerts.alerts;
          _pendingRequests = alerts.pendingRequests;
          _alertCount = alerts.alerts.length + alerts.pendingRequests.length;
        });

        if (isInitial) {
          _knownAlertAids = {
            ...alerts.alerts.map((c) => c.aid),
            ...alerts.pendingRequests.map((p) => p.aid),
          };
        }
      }
    } catch (e) {
      debugPrint('[MobileDashboard] Alerts load error: $e');
    }
  }

  Future<void> _pollAlerts() async {
    try {
      final alerts = await _coreService.getAlerts();
      if (!mounted) return;

      final currentAids = {
        ...alerts.alerts.map((c) => c.aid),
        ...alerts.pendingRequests.map((p) => p.aid),
      };

      final newAids = currentAids.difference(_knownAlertAids);

      setState(() {
        _alertContacts = alerts.alerts;
        _pendingRequests = alerts.pendingRequests;
        _alertCount = alerts.alerts.length + alerts.pendingRequests.length;
      });

      if (newAids.isNotEmpty) {
        final newAlert = alerts.alerts.where((c) => newAids.contains(c.aid)).firstOrNull;
        final newPending = newAlert == null
            ? alerts.pendingRequests.where((p) => newAids.contains(p.aid)).firstOrNull
            : null;
        final name = newAlert?.displayName ?? newPending?.displayName ?? 'Someone';
        _showAlertPopup(name);
      }

      _knownAlertAids = currentAids;
    } catch (e) {
      debugPrint('[MobileDashboard] Poll error: $e');
    }
  }

  void _showAlertPopup(String name) {
    _dismissPopup();

    final overlay = Overlay.of(context);
    _popupOverlay = OverlayEntry(
      builder: (ctx) => _AlertPopup(
        name: name,
        onTap: () {
          _dismissPopup();
          _tabController.animateTo(0);
        },
        onDismiss: _dismissPopup,
      ),
    );
    overlay.insert(_popupOverlay!);

    Future.delayed(const Duration(seconds: 5), _dismissPopup);
  }

  void _dismissPopup() {
    _popupOverlay?.remove();
    _popupOverlay = null;
  }

  Future<void> _onAcceptContact(String aid) async {
    try {
      await _coreService.acceptContact(aid);
      await _loadAlerts();
      _knownAlertAids.remove(aid);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Contact accepted')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to accept: $e')),
        );
      }
    }
  }

  Future<void> _onRejectContact(String aid) async {
    try {
      await _coreService.rejectContact(aid);
      await _loadAlerts();
      _knownAlertAids.remove(aid);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Contact rejected')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to reject: $e')),
        );
      }
    }
  }

  Future<void> _onDismissPending(String aid) async {
    try {
      await _coreService.deletePendingRequest(aid);
      await _loadAlerts();
      _knownAlertAids.remove(aid);
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to dismiss: $e')),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      bottom: false,
      child: Column(
        children: [
          _buildHeader(),
          Expanded(
            child: RefreshIndicator(
              onRefresh: _loadData,
              color: MobileColors.primary,
              child: SingleChildScrollView(
                physics: const AlwaysScrollableScrollPhysics(),
                child: Column(
                  children: [
                    const SizedBox(height: 8),
                    IdentityCard(
                      displayName: _displayName,
                      agentUrl: _agentUrl,
                      photoBase64: _photoBase64,
                    ),
                    const SizedBox(height: 16),
                    _buildTabs(),
                  ],
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildHeader() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      color: MobileColors.surface,
      child: Row(
        children: [
          GestureDetector(
            onTap: widget.onMenuTap,
            child: const Icon(Icons.menu, color: MobileColors.textPrimary, size: 28),
          ),
          const SizedBox(width: 12),
          const Expanded(
            child: Text(
              'Identity Agent',
              style: TextStyle(
                fontSize: 20,
                fontWeight: FontWeight.w700,
                color: MobileColors.textPrimary,
              ),
            ),
          ),
          IconButton(
            onPressed: () => _loadData(),
            icon: const Icon(Icons.refresh, color: MobileColors.textSecondary),
          ),
        ],
      ),
    );
  }

  Widget _buildTabs() {
    return Column(
      children: [
        Container(
          margin: const EdgeInsets.symmetric(horizontal: 16),
          decoration: BoxDecoration(
            color: MobileColors.surface,
            borderRadius: BorderRadius.circular(12),
          ),
          child: TabBar(
            controller: _tabController,
            labelColor: MobileColors.primary,
            unselectedLabelColor: MobileColors.textMuted,
            indicatorColor: MobileColors.primary,
            indicatorSize: TabBarIndicatorSize.tab,
            labelStyle: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
            unselectedLabelStyle: const TextStyle(fontSize: 13, fontWeight: FontWeight.w500),
            tabs: [
              Tab(
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Text('Alerts'),
                    if (_alertCount > 0) ...[
                      const SizedBox(width: 6),
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                        decoration: BoxDecoration(
                          color: MobileColors.error,
                          borderRadius: BorderRadius.circular(10),
                        ),
                        child: Text(
                          '$_alertCount',
                          style: const TextStyle(
                            color: MobileColors.textOnPrimary,
                            fontSize: 10,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                      ),
                    ],
                  ],
                ),
              ),
              const Tab(text: 'Tasks'),
              const Tab(text: 'Activity'),
            ],
          ),
        ),
        SizedBox(
          height: 400,
          child: TabBarView(
            controller: _tabController,
            children: [
              _buildAlertsTab(),
              _buildTasksTab(),
              _buildActivityTab(),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildAlertsTab() {
    if (_loading) {
      return const Center(child: CircularProgressIndicator(color: MobileColors.primary));
    }

    final items = <Widget>[];

    for (final contact in _alertContacts) {
      items.add(AlertCard(
        displayName: contact.displayName,
        aid: contact.aid,
        type: AlertCardType.connectionRequest,
        onApprove: () => _onAcceptContact(contact.aid),
        onDeny: () => _onRejectContact(contact.aid),
      ));
    }

    for (final pending in _pendingRequests) {
      items.add(AlertCard(
        displayName: pending.displayName,
        aid: pending.aid,
        type: AlertCardType.pendingRequest,
        subtitle: pending.errorReason,
        onDismiss: () => _onDismissPending(pending.aid),
      ));
    }

    if (items.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.notifications_none, size: 48, color: MobileColors.textMuted),
            const SizedBox(height: 12),
            const Text(
              'No alerts',
              style: TextStyle(color: MobileColors.textMuted, fontSize: 16),
            ),
          ],
        ),
      );
    }

    return ListView(
      padding: const EdgeInsets.symmetric(vertical: 8),
      children: items,
    );
  }

  Widget _buildTasksTab() {
    final tasks = BackgroundTask.dummyTasks();
    return ListView.builder(
      padding: const EdgeInsets.symmetric(vertical: 8),
      itemCount: tasks.length,
      itemBuilder: (context, index) => TaskCard(task: tasks[index]),
    );
  }

  Widget _buildActivityTab() {
    final entries = ActivityLogEntry.dummyEntries();
    return ListView.builder(
      padding: const EdgeInsets.symmetric(vertical: 8),
      itemCount: entries.length,
      itemBuilder: (context, index) => ActivityEntryWidget(entry: entries[index]),
    );
  }
}

class _AlertPopup extends StatefulWidget {
  final String name;
  final VoidCallback onTap;
  final VoidCallback onDismiss;

  const _AlertPopup({
    required this.name,
    required this.onTap,
    required this.onDismiss,
  });

  @override
  State<_AlertPopup> createState() => _AlertPopupState();
}

class _AlertPopupState extends State<_AlertPopup> with SingleTickerProviderStateMixin {
  late final AnimationController _controller;
  late final Animation<Offset> _slideAnimation;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 300),
    );
    _slideAnimation = Tween<Offset>(
      begin: const Offset(0, -1),
      end: Offset.zero,
    ).animate(CurvedAnimation(parent: _controller, curve: Curves.easeOut));
    _controller.forward();
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  String _getInitials(String name) {
    final parts = name.split(' ').where((w) => w.isNotEmpty).take(2);
    if (parts.isEmpty) return '?';
    return parts.map((w) => w[0].toUpperCase()).join();
  }

  @override
  Widget build(BuildContext context) {
    final topPadding = MediaQuery.of(context).padding.top;

    return Positioned(
      top: topPadding + 8,
      left: 16,
      right: 16,
      child: SlideTransition(
        position: _slideAnimation,
        child: Material(
          elevation: 8,
          borderRadius: BorderRadius.circular(12),
          shadowColor: MobileColors.cardShadow,
          child: GestureDetector(
            onTap: widget.onTap,
            child: Container(
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: MobileColors.surface,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: MobileColors.primary.withOpacity(0.3)),
              ),
              child: Row(
                children: [
                  CircleAvatar(
                    radius: 18,
                    backgroundColor: MobileColors.primary.withOpacity(0.12),
                    child: Text(
                      _getInitials(widget.name),
                      style: const TextStyle(
                        color: MobileColors.primary,
                        fontWeight: FontWeight.w700,
                        fontSize: 12,
                      ),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        const Text(
                          'New Connection Request',
                          style: TextStyle(
                            fontSize: 13,
                            fontWeight: FontWeight.w600,
                            color: MobileColors.primary,
                          ),
                        ),
                        const SizedBox(height: 2),
                        Text(
                          '${widget.name} wants to connect',
                          style: const TextStyle(
                            fontSize: 13,
                            color: MobileColors.textSecondary,
                          ),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ],
                    ),
                  ),
                  GestureDetector(
                    onTap: widget.onDismiss,
                    child: const Icon(Icons.close, size: 18, color: MobileColors.textMuted),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
