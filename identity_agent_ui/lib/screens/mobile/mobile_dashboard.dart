import 'dart:async';
import 'package:flutter/material.dart';
import '../../theme/mobile_theme.dart';
import '../../services/core_service.dart';
import '../../services/event_service.dart';
import '../../services/keri_service.dart';
import '../../config/agent_config.dart';
import '../../widgets/identity_card.dart';
import '../../widgets/alert_card.dart';
import '../../widgets/alert_detail_modal.dart';
import '../../widgets/confirmation_toast.dart';
import '../../widgets/activity_entry.dart';
import '../../widgets/setup_task_banner.dart';
import '../../widgets/key_storage_badge.dart';
import '../../models/activity_log_entry.dart';
import '../desktop/auth_management_screen.dart';

class MobileDashboard extends StatefulWidget {
  final String? serverUrl;
  final VoidCallback onMenuTap;
  final KeriService? keriService;

  const MobileDashboard({
    super.key,
    this.serverUrl,
    required this.onMenuTap,
    this.keriService,
  });

  @override
  State<MobileDashboard> createState() => MobileDashboardState();
}

class MobileDashboardState extends State<MobileDashboard> with SingleTickerProviderStateMixin {
  late final CoreService _coreService;
  late final EventService _eventService;
  late final TabController _tabController;
  StreamSubscription<AgentEvent>? _eventSub;
  Timer? _fallbackTimer;

  String _displayName = '';
  String _agentUrl = '';
  String? _photoBase64;
  List<ContactResponse> _alertContacts = [];
  List<PendingRequestResponse> _pendingRequests = [];
  List<CredentialRecord> _pendingCredentials = [];
  List<NotificationRecord> _notifications = [];
  int _alertCount = 0;
  bool _loading = true;
  List<TaskRecord> _backgroundTasks = [];

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 3, vsync: this);
    _coreService = CoreService(baseUrl: widget.serverUrl ?? AgentConfig.coreBaseUrl);
    _eventService = EventService.instance(widget.serverUrl ?? AgentConfig.coreBaseUrl);
    _loadData();
    _listenForEvents();
    _fallbackTimer = Timer.periodic(const Duration(seconds: 60), (_) => _loadAlerts());
  }

  @override
  void dispose() {
    _eventSub?.cancel();
    _fallbackTimer?.cancel();
    _tabController.dispose();
    _coreService.dispose();
    super.dispose();
  }

  void _listenForEvents() {
    _eventSub = _eventService.events.listen((event) {
      if (!mounted) return;
      if (event.type == 'introduction_received' || event.type == 'contact_accepted' ||
          event.type == 'pending_request_received' || event.type == 'credential_received' ||
          event.type == 'credential_accepted') {
        _loadAlerts();
      }
    });
  }

  Future<void> _loadData() async {
    await Future.wait([_loadProfile(), _loadEndpoint(), _loadAlerts(), _loadTasks()]);
    if (mounted) setState(() => _loading = false);
  }

  Future<void> _loadTasks() async {
    try {
      final result = await _coreService.getTasks();
      if (mounted) setState(() => _backgroundTasks = result.tasks);
    } catch (_) {}
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

  void refreshAlerts() => _loadAlerts();

  Future<void> _loadAlerts() async {
    try {
      final alerts = await _coreService.getAlerts();
      if (mounted) {
        setState(() {
          _alertContacts = alerts.alerts;
          _pendingRequests = alerts.pendingRequests;
          _pendingCredentials = alerts.pendingCredentials;
          _notifications = alerts.notifications;
          _alertCount = alerts.totalCount;
        });
      }
    } catch (e) {
      debugPrint('[MobileDashboard] Alerts load error: $e');
    }
  }

  Future<void> _onAcceptContact(String aid) async {
    try {
      await _coreService.acceptContact(aid);
      await _loadAlerts();
      if (mounted) {
        ConfirmationToast.show(context, message: 'Contact Added', icon: Icons.person_add);
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
      if (mounted) {
        ConfirmationToast.show(context,
          message: 'Contact Rejected',
          icon: Icons.person_off,
          color: const Color(0xFFDA1E28),
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

  Future<void> _onDismissNotification(String id) async {
    try {
      await _coreService.setNotificationStatus(id, 'dismissed');
      await _loadAlerts();
      if (mounted) {
        ConfirmationToast.show(context,
          message: 'Dismissed',
          icon: Icons.close,
          color: MobileColors.textMuted,
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to dismiss: $e')),
        );
      }
    }
  }

  Future<void> _onDismissPending(String aid) async {
    try {
      await _coreService.deletePendingRequest(aid);
      await _loadAlerts();
      if (mounted) {
        ConfirmationToast.show(context,
          message: 'Dismissed',
          icon: Icons.close,
          color: MobileColors.textMuted,
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to dismiss: $e')),
        );
      }
    }
  }

  Future<void> _onAcceptCredential(String said) async {
    try {
      await _coreService.acceptCredential(said);
      await _loadAlerts();
      if (mounted) {
        ConfirmationToast.show(context, message: 'Credential Accepted', icon: Icons.verified);
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to accept credential: $e')),
        );
      }
    }
  }

  Future<void> _onRejectCredential(String said) async {
    try {
      await _coreService.rejectCredential(said);
      await _loadAlerts();
      if (mounted) {
        ConfirmationToast.show(context,
          message: 'Credential Rejected',
          icon: Icons.cancel_outlined,
          color: const Color(0xFFDA1E28),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to reject credential: $e')),
        );
      }
    }
  }

  Future<void> _showContactDetail(ContactResponse contact) async {
    final action = await AlertDetailModal.showContactDetail(context, contact: contact);
    if (action == 'accept') {
      _onAcceptContact(contact.aid);
    } else if (action == 'reject') {
      _onRejectContact(contact.aid);
    }
  }

  Future<void> _showCredentialDetail(CredentialRecord cred) async {
    final action = await AlertDetailModal.showCredentialDetail(context, credential: cred);
    if (action == 'accept') {
      _onAcceptCredential(cred.said);
    } else if (action == 'reject') {
      _onRejectCredential(cred.said);
    }
  }

  Future<void> _showPendingDetail(PendingRequestResponse req) async {
    final action = await AlertDetailModal.showPendingDetail(context, request: req);
    if (action == 'dismiss') {
      _onDismissPending(req.aid);
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
                      onBadgeTap: () => Navigator.of(context).push(
                        MaterialPageRoute(
                          builder: (_) => const AuthManagementScreen(),
                        ),
                      ),
                    ),
                    Padding(
                      padding: const EdgeInsets.only(left: 32, bottom: 4),
                      child: const KeyStorageBadge(),
                    ),
                    if (widget.keriService != null)
                      SetupTaskBanner(
                        isMobile: true,
                        keriService: widget.keriService!,
                        serverUrl: widget.serverUrl,
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
        photo: contact.photo,
        onApprove: () => _onAcceptContact(contact.aid),
        onDeny: () => _onRejectContact(contact.aid),
        onTap: () => _showContactDetail(contact),
      ));
    }

    for (final pending in _pendingRequests) {
      items.add(AlertCard(
        displayName: pending.displayName,
        aid: pending.aid,
        type: AlertCardType.pendingRequest,
        subtitle: pending.errorReason,
        onDismiss: () => _onDismissPending(pending.aid),
        onTap: () => _showPendingDetail(pending),
      ));
    }

    for (final cred in _pendingCredentials) {
      final issuerDisplay = cred.issuerName.isNotEmpty ? cred.issuerName
          : (cred.issuerAid.length > 16 ? '${cred.issuerAid.substring(0, 12)}…' : cred.issuerAid);
      final typeDisplay = cred.credentialType.isNotEmpty ? cred.credentialType : 'Credential';
      items.add(AlertCard(
        displayName: issuerDisplay,
        aid: cred.issuerAid,
        type: AlertCardType.credentialIncoming,
        subtitle: typeDisplay,
        onApprove: () => _onAcceptCredential(cred.said),
        onDeny: () => _onRejectCredential(cred.said),
        onTap: () => _showCredentialDetail(cred),
      ));
    }

    // Listed first. The others are requests waiting on the user, which keep
    // until they are dealt with; a notification may be the only warning before
    // something stops, so burying it under three approvals gets it missed.
    final notificationCards = <Widget>[];
    for (final n in _notifications) {
      notificationCards.add(AlertCard(
        displayName: n.title,
        aid: n.fromAid,
        type: n.isCritical
            ? AlertCardType.notificationCritical
            : AlertCardType.notification,
        subtitle: n.body,
        onDismiss: () => _onDismissNotification(n.id),
      ));
    }
    items.insertAll(0, notificationCards);

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
    if (_backgroundTasks.isEmpty) {
      return const Center(
        child: Text(
          'No active tasks',
          style: TextStyle(color: MobileColors.textMuted, fontSize: 14),
        ),
      );
    }
    return ListView.builder(
      padding: const EdgeInsets.symmetric(vertical: 8),
      itemCount: _backgroundTasks.length,
      itemBuilder: (context, index) => _buildMobileTaskRow(_backgroundTasks[index]),
    );
  }

  Widget _buildMobileTaskRow(TaskRecord task) {
    Color statusColor;
    IconData statusIcon;
    String statusLabel;
    switch (task.status) {
      case 'in_progress':
        statusColor = MobileColors.primary;
        statusIcon = Icons.sync;
        statusLabel = 'In Progress';
      case 'completed':
        statusColor = MobileColors.success;
        statusIcon = Icons.check_circle;
        statusLabel = 'Completed';
      case 'failed':
        statusColor = MobileColors.error;
        statusIcon = Icons.error;
        statusLabel = 'Failed';
      default:
        statusColor = MobileColors.textMuted;
        statusIcon = Icons.schedule;
        statusLabel = 'Pending';
    }

    final title = _taskTypeLabel(task.type);

    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: MobileColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: MobileColors.border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  title,
                  style: const TextStyle(
                    fontSize: 14,
                    fontWeight: FontWeight.w600,
                    color: MobileColors.textPrimary,
                  ),
                ),
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                decoration: BoxDecoration(
                  color: statusColor.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(6),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(statusIcon, size: 12, color: statusColor),
                    const SizedBox(width: 4),
                    Text(statusLabel,
                        style: TextStyle(fontSize: 11, fontWeight: FontWeight.w600, color: statusColor)),
                  ],
                ),
              ),
            ],
          ),
          if (task.detail.isNotEmpty) ...[
            const SizedBox(height: 4),
            Text(task.detail,
                style: const TextStyle(fontSize: 12, color: MobileColors.textSecondary)),
          ],
          if (task.status == 'in_progress' && task.progress > 0) ...[
            const SizedBox(height: 10),
            ClipRRect(
              borderRadius: BorderRadius.circular(4),
              child: LinearProgressIndicator(
                value: task.progress / 100.0,
                backgroundColor: MobileColors.border,
                valueColor: AlwaysStoppedAnimation<Color>(statusColor),
                minHeight: 6,
              ),
            ),
            const SizedBox(height: 4),
            Align(
              alignment: Alignment.centerRight,
              child: Text('${task.progress}%',
                  style: const TextStyle(fontSize: 11, color: MobileColors.textMuted)),
            ),
          ],
        ],
      ),
    );
  }

  String _taskTypeLabel(String type) {
    switch (type) {
      case 'witness_request_sent': return 'Witness Request Sent';
      case 'witness_request_received': return 'Witness Request Received';
      case 'kel_sync': return 'KEL Synchronization';
      case 'credential_verification': return 'Credential Verification';
      case 'backup_identity': return 'Identity Backup';
      default: return type.replaceAll('_', ' ').split(' ')
          .map((w) => w.isEmpty ? '' : '${w[0].toUpperCase()}${w.substring(1)}')
          .join(' ');
    }
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
