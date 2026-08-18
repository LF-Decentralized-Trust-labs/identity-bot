import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:qr_flutter/qr_flutter.dart';
import '../../theme/app_theme.dart';
import 'package:agent_client/config/agent_config.dart';
import 'package:agent_client/services/camera_service.dart';
import '../../services/core_service.dart';
import 'package:agent_client/services/event_service.dart';
import 'package:agent_client/services/keri_service.dart';
import '../../widgets/identity_level_badge.dart';
import '../../widgets/key_storage_badge.dart';
import '../../widgets/alert_detail_modal.dart';
import 'credentials_screen.dart' show CredentialDetail;
import '../../widgets/confirmation_toast.dart';
import '../../widgets/log_entry.dart';
import '../../widgets/setup_task_banner.dart';
import '../auth_setup_screen.dart';
import '../qr_scanner_screen.dart';
import 'package:agent_client/services/scan_service.dart';
import '../../widgets/consent_modal.dart';

// Fallback share actions shown immediately while the backend is loading or
// unreachable. Mirrors the seeded rows in migration 7. The Data Manager sandbox
// app can replace these via PUT /api/share-actions at runtime.
const _kFallbackShareActions = [
  ShareAction(
    id: 'sa-add-contact',
    actionKey: 'add_contact',
    name: 'Add Contact',
    subtitle: 'Generate a shareable link so others can add you as a contact.',
    icon: 'person_add_outlined',
    isEnabled: true,
    sortOrder: 1,
  ),
  ShareAction(
    id: 'sa-request-payment',
    actionKey: 'request_payment',
    name: 'Request Payment',
    subtitle: 'Send a payment request to a contact.',
    icon: 'payment_outlined',
    isEnabled: false,
    sortOrder: 3,
  ),
  ShareAction(
    id: 'sa-share-file',
    actionKey: 'share_file',
    name: 'Share a File',
    subtitle: 'Send an encrypted file to a contact.',
    icon: 'attach_file',
    isEnabled: false,
    sortOrder: 4,
  ),
];

/// Desktop dashboard — 3-section layout designed for full-width desktop.
///
/// Sections: Identity (left) | Notifications (center) | Engagement (right)
class DesktopDashboardScreen extends StatefulWidget {
  final KeriService keriService;
  final String? serverUrl;

  const DesktopDashboardScreen({super.key, required this.keriService, this.serverUrl});

  @override
  State<DesktopDashboardScreen> createState() => _DesktopDashboardScreenState();
}

class _DesktopDashboardScreenState extends State<DesktopDashboardScreen> {
  late final CoreService _coreService = CoreService(baseUrl: _resolveServerUrl());

  String? _resolveServerUrl() {
    if (widget.serverUrl != null) return widget.serverUrl;
    return null;
  }

  // Identity
  IdentityResponse? _identity;
  ProfileResponse? _profile;
  // Notifications
  List<ContactResponse> _alerts = [];
  List<PendingRequestResponse> _pendingRequests = [];
  List<CredentialRecord> _pendingCredentials = [];
  List<NotificationRecord> _notifications = [];

  // Automated background tasks (from backend)
  List<TaskRecord> _backgroundTasks = [];

  // Activity
  final List<LogEntry> _logs = [];

  // Engagement — pre-seeded with fallback so the card is never empty while loading
  List<ShareAction> _shareActions = _kFallbackShareActions;
  bool _cameraAvailable = false;
  bool _scanProcessing = false;

  // OOBI — loaded for identity card server URL
  OobiResponse? _oobi;

  // Status
  HealthResponse? _health;
  CoreConnectionState _connectionState = CoreConnectionState.disconnected;

  Timer? _healthTimer;
  Timer? _alertTimer;
  StreamSubscription<AgentEvent>? _eventSub;

  @override
  void initState() {
    super.initState();
    _addLog('Dashboard initialized', LogLevel.info);
    _load();
    _detectCamera();
    _subscribeToEvents();
  }

  void _subscribeToEvents() {
    final serverUrl = widget.serverUrl ?? AgentConfig.coreBaseUrl;
    final eventService = EventService.instance(serverUrl);
    _eventSub = eventService.events.listen((event) {
      if (!mounted) return;
      if (event.type == 'introduction_received' ||
          event.type == 'contact_accepted' ||
          event.type == 'pending_request_received' ||
          event.type == 'credential_received' ||
          event.type == 'credential_accepted') {
        _fetchAlerts();
      }
    });
  }

  Future<void> _detectCamera() async {
    final available = await detectCamera();
    if (mounted) setState(() => _cameraAvailable = available);
  }

  @override
  void dispose() {
    _healthTimer?.cancel();
    _alertTimer?.cancel();
    _eventSub?.cancel();
    _coreService.dispose();
    super.dispose();
  }

  void _addLog(String message, LogLevel level) {
    if (!mounted) return;
    setState(() {
      _logs.insert(0, LogEntry(message: message, timestamp: _timeNow(), level: level));
      if (_logs.length > 30) _logs.removeLast();
    });
  }

  String _timeNow() {
    final now = DateTime.now();
    return '${now.hour.toString().padLeft(2, '0')}:${now.minute.toString().padLeft(2, '0')}:${now.second.toString().padLeft(2, '0')}';
  }

  Future<void> _load() async {
    setState(() => _connectionState = CoreConnectionState.connecting);
    try {
      final health = await _coreService.getHealth();
      setState(() {
        _health = health;
        _connectionState = health.isActive ? CoreConnectionState.connected : CoreConnectionState.error;
      });
      if (health.isActive) {
        _addLog('Connected to ${health.agent} v${health.version}', LogLevel.success);
        await Future.wait([_loadIdentityData(), _loadTasks(), _loadShareActions()]);
        _startPolling();
      }
    } catch (e) {
      if (mounted) {
        setState(() => _connectionState = CoreConnectionState.error);
        _addLog('Connection failed: ${e.toString().split(': ').last}', LogLevel.error);
      }
    }
  }

  Future<void> _loadIdentityData() async {
    try {
      final results = await Future.wait([
        _coreService.getIdentity(),
        _coreService.getProfile(),
        _coreService.getOobi(),
      ]);
      if (mounted) {
        setState(() {
          _identity = results[0] as IdentityResponse;
          _profile = results[1] as ProfileResponse;
          _oobi = results[2] as OobiResponse;
        });
        if ((_identity?.initialized ?? false) && _identity?.aid != null) {
          _addLog('Identity: ${_identity!.aid!.substring(0, 12)}…', LogLevel.info);
        }
      }
    } catch (_) {}
  }

  Future<void> _loadTasks() async {
    try {
      final result = await _coreService.getTasks();
      if (mounted) setState(() => _backgroundTasks = result.tasks);
    } catch (_) {}
  }

  Future<void> _loadShareActions() async {
    try {
      final actions = await _coreService.getShareActions();
      if (mounted && actions.isNotEmpty) {
        setState(() => _shareActions = actions);
      }
    } catch (_) {
      // Keep fallback list already set in field initializer
    }
  }

  Future<void> _fetchAlerts() async {
    try {
      final result = await _coreService.getAlerts();
      if (mounted) {
        setState(() {
          _alerts = result.alerts;
          _pendingRequests = result.pendingRequests;
          _pendingCredentials = result.pendingCredentials;
          _notifications = result.notifications;
        });
      }
    } catch (_) {}
  }

  void _startPolling() {
    _fetchAlerts();
    _alertTimer = Timer.periodic(const Duration(seconds: 15), (_) => _fetchAlerts());
    _healthTimer = Timer.periodic(Duration(seconds: AgentConfig.healthPollIntervalSeconds), (_) async {
      try {
        final h = await _coreService.getHealth();
        if (mounted) {
          setState(() {
            _health = h;
            _connectionState = h.isActive ? CoreConnectionState.connected : CoreConnectionState.error;
          });
        }
      } catch (_) {
        if (mounted) setState(() => _connectionState = CoreConnectionState.error);
      }
    });
  }

  Future<void> _acceptContact(String aid) async {
    try {
      await _coreService.acceptContact(aid);
      _addLog('Contact accepted', LogLevel.success);
      _fetchAlerts();
      if (mounted) {
        ConfirmationToast.show(context, message: 'Contact Added', icon: Icons.person_add);
      }
    } catch (e) {
      _addLog('Accept failed: ${e.toString().split(': ').last}', LogLevel.error);
    }
  }

  Future<void> _rejectContact(String aid) async {
    try {
      await _coreService.rejectContact(aid);
      _addLog('Contact rejected', LogLevel.info);
      _fetchAlerts();
      if (mounted) {
        ConfirmationToast.show(context,
          message: 'Contact Rejected',
          icon: Icons.person_off,
          color: AppColors.error,
        );
      }
    } catch (e) {
      _addLog('Reject failed: ${e.toString().split(': ').last}', LogLevel.error);
    }
  }

  Future<void> _dismissPendingRequest(String aid) async {
    try {
      await _coreService.deletePendingRequest(aid);
      _fetchAlerts();
      if (mounted) {
        ConfirmationToast.show(context,
          message: 'Dismissed',
          icon: Icons.close,
          color: AppColors.textMuted,
        );
      }
    } catch (_) {}
  }

  Future<void> _acceptCredential(String said) async {
    try {
      await _coreService.acceptCredential(said);
      _addLog('Credential accepted', LogLevel.success);
      _fetchAlerts();
      if (mounted) {
        ConfirmationToast.show(context, message: 'Credential Accepted', icon: Icons.verified);
      }
    } catch (e) {
      _addLog('Accept failed: ${e.toString().split(': ').last}', LogLevel.error);
    }
  }

  Future<void> _rejectCredential(String said) async {
    try {
      await _coreService.rejectCredential(said);
      _addLog('Credential rejected', LogLevel.info);
      _fetchAlerts();
      if (mounted) {
        ConfirmationToast.show(context,
          message: 'Credential Rejected',
          icon: Icons.cancel_outlined,
          color: AppColors.error,
        );
      }
    } catch (e) {
      _addLog('Reject failed: ${e.toString().split(': ').last}', LogLevel.error);
    }
  }

  Future<void> _showContactDetail(ContactResponse contact) async {
    final action = await AlertDetailModal.showContactDetail(context, contact: contact);
    if (action == 'accept') {
      _acceptContact(contact.aid);
    } else if (action == 'reject') {
      _rejectContact(contact.aid);
    }
  }

  Future<void> _showCredentialDetail(CredentialRecord cred) async {
    final action = await showDialog<String>(
      context: context,
      barrierDismissible: true,
      builder: (ctx) => Dialog(
        backgroundColor: Theme.of(ctx).colorScheme.surface,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 560, maxHeight: 680),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Flexible(
                child: CredentialDetail(
                  cred: cred,
                  onClose: () => Navigator.pop(ctx),
                  onDelete: () => Navigator.pop(ctx),
                  onVerify: () {},
                  serverUrl: widget.serverUrl,
                ),
              ),
              // Accept / Reject actions for pending credentials
              Container(
                padding: const EdgeInsets.fromLTRB(20, 0, 20, 16),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.end,
                  children: [
                    TextButton(
                      onPressed: () => Navigator.pop(ctx, 'reject'),
                      style: TextButton.styleFrom(foregroundColor: AppColors.error),
                      child: const Text('Reject'),
                    ),
                    const SizedBox(width: 8),
                    ElevatedButton(
                      onPressed: () => Navigator.pop(ctx, 'accept'),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: AppColors.success,
                        foregroundColor: Colors.white,
                        elevation: 0,
                      ),
                      child: const Text('Accept'),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
    if (action == 'accept') {
      _acceptCredential(cred.said);
    } else if (action == 'reject') {
      _rejectCredential(cred.said);
    }
  }

  Future<void> _showPendingDetail(PendingRequestResponse req) async {
    final action = await AlertDetailModal.showPendingDetail(context, request: req);
    if (action == 'dismiss') {
      _dismissPendingRequest(req.aid);
    }
  }

  void _onScanTap() {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => QrScannerScreen(
          onScanned: (scannedData) {
            Navigator.of(context).pop();
            _handleScannedUrl(scannedData);
          },
        ),
      ),
    );
  }

  /// Parses a scanned URL, determines the action, and routes accordingly.
  /// Matches the mobile MobileQrScanner behavior.
  /// Dumb router: forward whatever was scanned to the Go core's scan gate, which fetches the
  /// Ask, reads its action `t`, and decides what to do. No per-transaction logic lives here —
  /// adding a new transaction type is a Go-only change. This mirrors the mobile scanner; the
  /// desktop just renders the generic consent Go returns and sends back the user's decision.
  void _handleScannedUrl(String scannedUrl) {
    if (_scanProcessing) return;
    setState(() => _scanProcessing = true);
    _runScan(scannedUrl);
  }

  Future<void> _runScan(String url) async {
    final scan = ScanService(baseUrl: _coreService.baseUrl);
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Row(
          children: [
            SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white)),
            SizedBox(width: 12),
            Text('Reading request...'),
          ],
        ),
        duration: Duration(seconds: 15),
      ),
    );
    try {
      final preview = await scan.decode(url);
      if (!mounted) return;
      ScaffoldMessenger.of(context).hideCurrentSnackBar();

      final details = preview.details
          .map((d) => ConsentDetailItem(
                label: d.label.replaceAll('_', ' '),
                value: d.value.isEmpty ? '—' : d.value,
                isMonospace: d.label.contains('aid') || d.label.contains('email'),
              ))
          .toList();

      final result = await ConsentModal.show(
        context: context,
        title: preview.title,
        subtitle: preview.subtitle,
        name: preview.counterparty,
        avatarLabel: preview.counterparty.isNotEmpty
            ? preview.counterparty[0].toUpperCase()
            : '?',
        details: details,
        confirmLabel: 'Approve',
        cancelLabel: 'Deny',
        accentColor: AppColors.accent,
        icon: preview.action == 'login'
            ? Icons.login_rounded
            : Icons.person_add_alt_1_rounded,
        warningMessage: preview.warning,
      );

      if (result?.confirmed == true) {
        await scan.execute(url,
            approved: true,
            tier: preview.defaultTier,
            askDigest: preview.askDigest);
        if (mounted) {
          final msg = preview.action == 'login'
              ? 'Signed in successfully'
              : preview.action == 'add_contact'
                  ? 'Contact added'
                  : 'Done';
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text(msg), backgroundColor: AppColors.coreActive),
          );
          _load();
        }
      } else if (result?.confirmed == false) {
        await scan.execute(url,
            approved: false, askDigest: preview.askDigest);
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).hideCurrentSnackBar();
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Scan failed: ${e.toString().split(': ').last}'),
            backgroundColor: AppColors.error,
          ),
        );
      }
    } finally {
      scan.dispose();
      if (mounted) setState(() => _scanProcessing = false);
    }
  }

  void _showShareQrDialog() {
    showDialog(
      context: context,
      builder: (_) => _ShareQrDialog(
        coreService: _coreService,
        actions: _shareActions,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final totalAlerts = _alerts.length + _pendingRequests.length + _pendingCredentials.length + _notifications.length;

    return Scaffold(
      body: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(24, 24, 24, 24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _buildHeader(),
            SetupTaskBanner(
              isMobile: false,
              keriService: widget.keriService,
              serverUrl: widget.serverUrl,
            ),
            const SizedBox(height: 20),
            // 2-column dashboard layout
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // ── Identity column ──────────────────────────────────────
                Expanded(
                  flex: 3,
                  child: _buildIdentitySection(),
                ),
                const SizedBox(width: 16),
                // ── Notifications column — 3 stacked cards ───────────────
                Expanded(
                  flex: 4,
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      _buildAlertsCard(totalAlerts),
                      const SizedBox(height: 12),
                      _buildTasksCard(),
                      const SizedBox(height: 12),
                      _buildDashboardActivityCard(),
                    ],
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildHeader() {
    final isConnected = _connectionState == CoreConnectionState.connected;
    return Row(
      children: [
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text('Dashboard', style: Theme.of(context).textTheme.headlineMedium),
              const SizedBox(height: 4),
              const Text('Your identity at a glance.',
                  style: TextStyle(color: AppColors.textSecondary, fontSize: 14)),
            ],
          ),
        ),
        Container(
          width: 8,
          height: 8,
          decoration: BoxDecoration(
            color: isConnected ? AppColors.success : AppColors.error,
            shape: BoxShape.circle,
          ),
        ),
        const SizedBox(width: 6),
        Text(
          isConnected ? 'Connected' : _connectionState == CoreConnectionState.connecting ? 'Connecting…' : 'Disconnected',
          style: TextStyle(
            color: isConnected ? AppColors.success : AppColors.textMuted,
            fontSize: 12,
          ),
        ),
        const SizedBox(width: 12),
        IconButton(
          onPressed: _load,
          icon: const Icon(Icons.refresh),
          color: AppColors.textSecondary,
          tooltip: 'Refresh',
          iconSize: 18,
        ),
        const SizedBox(width: 8),
        FilledButton.icon(
          onPressed: _showShareQrDialog,
          icon: const Icon(Icons.share_outlined, size: 16),
          label: const Text('Share Code',
              style: TextStyle(fontSize: 13, fontWeight: FontWeight.w500, letterSpacing: 0.2)),
          style: FilledButton.styleFrom(
            backgroundColor: AppColors.primary,
            foregroundColor: Colors.white,
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
            minimumSize: const Size(0, 36),
            tapTargetSize: MaterialTapTargetSize.shrinkWrap,
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
            elevation: 0,
          ),
        ),
        const SizedBox(width: 8),
        FilledButton.icon(
          onPressed: _cameraAvailable ? _onScanTap : null,
          icon: const Icon(Icons.qr_code_scanner, size: 16),
          label: const Text('Scan',
              style: TextStyle(fontSize: 13, fontWeight: FontWeight.w500, letterSpacing: 0.2)),
          style: FilledButton.styleFrom(
            backgroundColor: _cameraAvailable ? AppColors.accent : AppColors.textMuted,
            foregroundColor: Colors.white,
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
            minimumSize: const Size(0, 36),
            tapTargetSize: MaterialTapTargetSize.shrinkWrap,
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
            elevation: 0,
          ),
        ),
      ],
    );
  }

  Widget _buildIdentitySection() {
    final hasIdentity = _identity?.initialized == true && _identity?.aid != null;
    final name = _profile?.fullName.isNotEmpty == true ? _profile!.fullName : 'Identity Agent';
    final serverUrl = _oobi?.endpointUrl.isNotEmpty == true
        ? _oobi!.endpointUrl
        : _oobi?.baseUrl ?? '';

    return Container(
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [
            AppColors.primary.withOpacity(0.08),
            AppColors.surface,
          ],
        ),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: AppColors.primary.withOpacity(0.15)),
      ),
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // ── Avatar + Name + Badge ──────────────────────────────
          Row(
            children: [
              _buildProfileAvatar(),
              const SizedBox(width: 14),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(name,
                        style: const TextStyle(fontSize: 18, fontWeight: FontWeight.w700,
                            color: AppColors.textPrimary),
                        maxLines: 1, overflow: TextOverflow.ellipsis),
                    if (_profile?.org.isNotEmpty == true)
                      Text(_profile!.org,
                          style: const TextStyle(fontSize: 12, color: AppColors.textMuted),
                          maxLines: 1, overflow: TextOverflow.ellipsis),
                  ],
                ),
              ),
              if (hasIdentity)
                LiveIdentityLevelBadge(
                  onTap: () => Navigator.of(context).push(
                    MaterialPageRoute(builder: (_) => const AuthSetupScreen()),
                  ),
                ),
            ],
          ),

          if (hasIdentity) ...[
            const SizedBox(height: 18),
            // ── AID ──────────────────────────────────────────────
            _identityField(
              label: 'Your Identifier (AID)',
              value: _identity!.aid!,
              monospace: true,
              copiable: true,
            ),

            // ── Server URL ───────────────────────────────────────
            if (serverUrl.isNotEmpty) ...[
              const SizedBox(height: 12),
              _identityField(
                label: 'Agent Address',
                value: serverUrl,
                monospace: false,
                copiable: true,
              ),
            ],

            const SizedBox(height: 14),
            // ── Status row ───────────────────────────────────────
            Row(
              children: [
                KeyStorageBadge(coreService: _coreService),
                const SizedBox(width: 10),
                if (_identity!.eventCount != null)
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                    decoration: BoxDecoration(
                      color: AppColors.primary.withOpacity(0.08),
                      borderRadius: BorderRadius.circular(6),
                    ),
                    child: Text(
                      '${_identity!.eventCount} key event${_identity!.eventCount == 1 ? '' : 's'}',
                      style: const TextStyle(color: AppColors.primary, fontSize: 11, fontWeight: FontWeight.w500),
                    ),
                  ),
              ],
            ),
          ] else if (_connectionState == CoreConnectionState.connected) ...[
            const SizedBox(height: 16),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: AppColors.warning.withOpacity(0.08),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: AppColors.warning.withOpacity(0.3)),
              ),
              child: const Row(
                children: [
                  Icon(Icons.warning_amber_rounded, color: AppColors.warning, size: 16),
                  SizedBox(width: 8),
                  Expanded(
                    child: Text('No identity found. Complete the setup wizard.',
                        style: TextStyle(color: AppColors.textSecondary, fontSize: 12)),
                  ),
                ],
              ),
            ),
          ] else ...[
            const SizedBox(height: 20),
            const Center(child: CircularProgressIndicator()),
          ],
        ],
      ),
    );
  }

  Widget _identityField({
    required String label,
    required String value,
    required bool monospace,
    required bool copiable,
  }) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label,
            style: const TextStyle(fontSize: 10, fontWeight: FontWeight.w600,
                color: AppColors.textMuted, letterSpacing: 0.5)),
        const SizedBox(height: 3),
        InkWell(
          onTap: copiable ? () {
            Clipboard.setData(ClipboardData(text: value));
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(content: Text('Copied: ${value.length > 30 ? '${value.substring(0, 30)}...' : value}'),
                  duration: const Duration(seconds: 1)),
            );
          } : null,
          borderRadius: BorderRadius.circular(6),
          child: Container(
            width: double.infinity,
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 7),
            decoration: BoxDecoration(
              color: AppColors.surface,
              borderRadius: BorderRadius.circular(6),
              border: Border.all(color: AppColors.border),
            ),
            child: Row(
              children: [
                Expanded(
                  child: Text(
                    value,
                    style: TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 11,
                      fontFamily: monospace ? 'monospace' : null,
                      height: 1.3,
                    ),
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                if (copiable)
                  const Padding(
                    padding: EdgeInsets.only(left: 6),
                    child: Icon(Icons.copy, size: 12, color: AppColors.textMuted),
                  ),
              ],
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildProfileAvatar() {
    if (_profile?.photo != null && _profile!.photo.isNotEmpty) {
      try {
        final bytes = base64Decode(_profile!.photo);
        return CircleAvatar(radius: 24, backgroundImage: MemoryImage(bytes));
      } catch (_) {
        return _initialsAvatar();
      }
    }
    return _initialsAvatar();
  }

  Widget _buildProfileHeader() {
    Widget avatar;
    if (_profile?.photo != null && _profile!.photo.isNotEmpty) {
      try {
        final bytes = base64Decode(_profile!.photo);
        avatar = CircleAvatar(radius: 24, backgroundImage: MemoryImage(bytes));
      } catch (_) {
        avatar = _initialsAvatar();
      }
    } else {
      avatar = _initialsAvatar();
    }

    final name = _profile?.fullName.isNotEmpty == true
        ? _profile!.fullName
        : 'Identity Agent';

    final hasIdentity = _identity?.initialized == true && _identity?.aid != null;
    return Row(
      children: [
        avatar,
        const SizedBox(width: 12),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(name,
                  style: const TextStyle(fontSize: 15, fontWeight: FontWeight.w600,
                      color: AppColors.textPrimary),
                  maxLines: 1, overflow: TextOverflow.ellipsis),
              if (_profile?.org.isNotEmpty == true)
                Text(_profile!.org,
                    style: const TextStyle(fontSize: 12, color: AppColors.textMuted),
                    maxLines: 1, overflow: TextOverflow.ellipsis),
            ],
          ),
        ),
        if (hasIdentity) ...[
          const SizedBox(width: 8),
          LiveIdentityLevelBadge(
            onTap: () => Navigator.of(context).push(
              MaterialPageRoute(builder: (_) => const AuthSetupScreen()),
            ),
          ),
        ],
      ],
    );
  }

  Widget _initialsAvatar() {
    final name = _profile?.fullName ?? '';
    final initials = name.isNotEmpty
        ? name.split(' ').take(2).map((w) => w.isNotEmpty ? w[0].toUpperCase() : '').join()
        : 'IA';
    return CircleAvatar(
      radius: 24,
      backgroundColor: AppColors.primary,
      child: Text(initials.isNotEmpty ? initials : 'IA',
          style: const TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.w600)),
    );
  }

  // ── Alerts card ────────────────────────────────────────────────────────────

  Widget _buildAlertsCard(int totalAlerts) {
    return _sectionCard(
      title: 'Alerts',
      icon: Icons.notifications_outlined,
      trailing: totalAlerts > 0
          ? Container(
              padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
              decoration: BoxDecoration(
                color: AppColors.corePending.withOpacity(0.15),
                borderRadius: BorderRadius.circular(10),
              ),
              child: Text('$totalAlerts',
                  style: const TextStyle(color: AppColors.corePending,
                      fontSize: 11, fontWeight: FontWeight.w700)),
            )
          : null,
      child: _alerts.isNotEmpty || _pendingRequests.isNotEmpty || _pendingCredentials.isNotEmpty || _notifications.isNotEmpty
          ? Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // First. The others wait on the user and keep until dealt
                // with; a notification may be the only warning before something
                // stops.
                ..._notifications.take(3).map((n) => _notificationItem(n)),
                ..._alerts.take(3).map((a) => _alertItem(a)),
                ..._pendingRequests.take(2).map((r) => _pendingItem(r)),
                ..._pendingCredentials.take(3).map((c) => _credentialAlertItem(c)),
                if (totalAlerts > 8)
                  Padding(
                    padding: const EdgeInsets.only(top: 4),
                    child: Text('+ ${totalAlerts - 8} more…',
                        style: const TextStyle(color: AppColors.textMuted, fontSize: 11)),
                  ),
              ],
            )
          : const Text('No pending alerts.',
              style: TextStyle(color: AppColors.textMuted, fontSize: 12)),
    );
  }

  // ── Tasks card ─────────────────────────────────────────────────────────────

  Widget _buildTasksCard() {
    final activeTasks = _backgroundTasks
        .where((t) => t.status == 'pending' || t.status == 'in_progress')
        .toList();

    return _sectionCard(
      title: 'Tasks',
      icon: Icons.task_alt_outlined,
      trailing: activeTasks.isNotEmpty
          ? Container(
              padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
              decoration: BoxDecoration(
                color: AppColors.accent.withOpacity(0.15),
                borderRadius: BorderRadius.circular(10),
              ),
              child: Text('${activeTasks.length}',
                  style: const TextStyle(color: AppColors.accent,
                      fontSize: 11, fontWeight: FontWeight.w700)),
            )
          : null,
      child: _backgroundTasks.isEmpty
          ? const Text(
              'No active tasks',
              style: TextStyle(color: AppColors.textMuted, fontSize: 12),
            )
          : Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: _backgroundTasks.take(5).map(_buildTaskRow).toList()
                ..addAll(_backgroundTasks.length > 5
                    ? [Padding(
                        padding: const EdgeInsets.only(top: 4),
                        child: Text(
                          '+ ${_backgroundTasks.length - 5} more…',
                          style: const TextStyle(color: AppColors.textMuted, fontSize: 11),
                        ),
                      )]
                    : []),
            ),
    );
  }

  Widget _buildTaskRow(TaskRecord task) {
    Color statusColor;
    IconData statusIcon;
    switch (task.status) {
      case 'in_progress':
        statusColor = AppColors.accent;
        statusIcon = Icons.sync;
      case 'completed':
        statusColor = AppColors.success;
        statusIcon = Icons.check_circle_outline;
      case 'failed':
        statusColor = AppColors.error;
        statusIcon = Icons.error_outline;
      default:
        statusColor = AppColors.textMuted;
        statusIcon = Icons.schedule_outlined;
    }

    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        children: [
          Icon(statusIcon, size: 14, color: statusColor),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  _taskTypeLabel(task.type),
                  style: TextStyle(
                    fontSize: 12,
                    color: task.status == 'completed'
                        ? AppColors.textMuted
                        : AppColors.textPrimary,
                    decoration: task.status == 'completed'
                        ? TextDecoration.lineThrough
                        : null,
                  ),
                ),
                if (task.detail.isNotEmpty)
                  Text(task.detail,
                      style: const TextStyle(fontSize: 10, color: AppColors.textMuted)),
              ],
            ),
          ),
          if (task.status == 'in_progress' && task.progress > 0) ...[
            const SizedBox(width: 8),
            Text('${task.progress}%',
                style: const TextStyle(fontSize: 10, color: AppColors.textMuted)),
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

  // ── Activity card ──────────────────────────────────────────────────────────

  Widget _buildDashboardActivityCard() {
    return _sectionCard(
      title: 'Activity',
      icon: Icons.history,
      child: const Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _DashActivityRow(icon: Icons.fingerprint, label: 'Identity created', color: AppColors.success),
          SizedBox(height: 6),
          _DashActivityRow(icon: Icons.vpn_key, label: 'Keys generated', color: AppColors.primary),
          SizedBox(height: 10),
          Text('Full history available in History →',
              style: TextStyle(color: AppColors.textMuted, fontSize: 11)),
        ],
      ),
    );
  }

  Widget _alertItem(ContactResponse alert) {
    return GestureDetector(
      onTap: () => _showContactDetail(alert),
      child: Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: AppColors.surfaceLight,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: AppColors.border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              CircleAvatar(
                radius: 14,
                backgroundColor: AppColors.corePending.withOpacity(0.12),
                child: Text(
                  alert.displayName.isNotEmpty ? alert.displayName[0].toUpperCase() : '?',
                  style: const TextStyle(color: AppColors.corePending, fontSize: 12,
                      fontWeight: FontWeight.w600),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: Text(alert.displayName,
                    style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w600,
                        color: AppColors.textPrimary)),
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
                decoration: BoxDecoration(
                  color: AppColors.corePending.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(3),
                ),
                child: const Text('INCOMING',
                    style: TextStyle(color: AppColors.corePending, fontSize: 8,
                        fontWeight: FontWeight.w700, letterSpacing: 0.8)),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Row(
            mainAxisAlignment: MainAxisAlignment.end,
            children: [
              TextButton(
                onPressed: () => _rejectContact(alert.aid),
                style: TextButton.styleFrom(
                  foregroundColor: AppColors.error,
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                  minimumSize: Size.zero,
                  tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                ),
                child: const Text('Reject', style: TextStyle(fontSize: 12)),
              ),
              const SizedBox(width: 6),
              ElevatedButton(
                onPressed: () => _acceptContact(alert.aid),
                style: ElevatedButton.styleFrom(
                  backgroundColor: AppColors.success,
                  foregroundColor: Colors.white,
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                  minimumSize: Size.zero,
                  tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                  elevation: 0,
                ),
                child: const Text('Accept', style: TextStyle(fontSize: 12)),
              ),
            ],
          ),
        ],
      ),
    ),
    );
  }

  Widget _pendingItem(PendingRequestResponse req) {
    return GestureDetector(
      onTap: () => _showPendingDetail(req),
      child: Container(
        margin: const EdgeInsets.only(bottom: 8),
        padding: const EdgeInsets.all(10),
        decoration: BoxDecoration(
          color: AppColors.surfaceLight,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: AppColors.error.withOpacity(0.3)),
        ),
        child: Row(
          children: [
            const Icon(Icons.link_off, color: AppColors.error, size: 16),
            const SizedBox(width: 8),
            Expanded(
              child: Text(req.displayName,
                  style: const TextStyle(fontSize: 12, color: AppColors.textPrimary)),
            ),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
              decoration: BoxDecoration(
                color: AppColors.error.withOpacity(0.1),
                borderRadius: BorderRadius.circular(3),
              ),
              child: const Text('FAILED',
                  style: TextStyle(color: AppColors.error, fontSize: 8,
                      fontWeight: FontWeight.w700, letterSpacing: 0.8)),
            ),
            const SizedBox(width: 6),
            TextButton(
              onPressed: () => _dismissPendingRequest(req.aid),
              style: TextButton.styleFrom(
                foregroundColor: AppColors.textMuted,
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                minimumSize: Size.zero,
                tapTargetSize: MaterialTapTargetSize.shrinkWrap,
              ),
              child: const Text('Dismiss', style: TextStyle(fontSize: 11)),
            ),
          ],
        ),
      ),
    );
  }

  Widget _notificationItem(NotificationRecord n) {
    final accent = n.isCritical ? AppColors.error : AppColors.primary;
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: AppColors.surfaceLight,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: accent.withOpacity(0.3)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(n.isCritical ? Icons.warning_amber_rounded : Icons.notifications_outlined,
                  size: 14, color: accent),
              const SizedBox(width: 6),
              Expanded(
                child: Text(n.title,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(
                        color: AppColors.textPrimary, fontSize: 12, fontWeight: FontWeight.w600)),
              ),
            ],
          ),
          if (n.body.isNotEmpty)
            Padding(
              padding: const EdgeInsets.only(top: 4),
              child: Text(n.body,
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(color: AppColors.textMuted, fontSize: 11)),
            ),
        ],
      ),
    );
  }

  Widget _credentialAlertItem(CredentialRecord cred) {
    final issuerDisplay = cred.issuerName.isNotEmpty ? cred.issuerName
        : (cred.issuerAid.length > 16 ? '${cred.issuerAid.substring(0, 12)}…' : cred.issuerAid);
    final typeDisplay = cred.credentialType.isNotEmpty ? cred.credentialType : 'Credential';
    return GestureDetector(
      onTap: () => _showCredentialDetail(cred),
      child: Container(
        margin: const EdgeInsets.only(bottom: 8),
        padding: const EdgeInsets.all(10),
        decoration: BoxDecoration(
          color: AppColors.surfaceLight,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: AppColors.success.withOpacity(0.3)),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.verified_outlined, size: 14, color: AppColors.success),
                const SizedBox(width: 6),
                Expanded(
                  child: Text('$typeDisplay from $issuerDisplay',
                      style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w600,
                          color: AppColors.textPrimary),
                      maxLines: 1, overflow: TextOverflow.ellipsis),
                ),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
                  decoration: BoxDecoration(
                    color: AppColors.success.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(3),
                  ),
                  child: const Text('CREDENTIAL',
                      style: TextStyle(color: AppColors.success, fontSize: 8,
                          fontWeight: FontWeight.w700, letterSpacing: 0.8)),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Row(
              mainAxisAlignment: MainAxisAlignment.end,
              children: [
                TextButton(
                  onPressed: () => _rejectCredential(cred.said),
                  style: TextButton.styleFrom(
                    foregroundColor: AppColors.error,
                    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                    minimumSize: Size.zero,
                    tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                  ),
                  child: const Text('Reject', style: TextStyle(fontSize: 12)),
                ),
                const SizedBox(width: 6),
                ElevatedButton(
                  onPressed: () => _acceptCredential(cred.said),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: AppColors.success,
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                    minimumSize: Size.zero,
                    tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                    elevation: 0,
                  ),
                  child: const Text('Accept', style: TextStyle(fontSize: 12)),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _sectionCard({
    required String title,
    required IconData icon,
    required Widget child,
    Widget? trailing,
  }) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppColors.border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, size: 16, color: AppColors.textSecondary),
              const SizedBox(width: 8),
              Text(title,
                  style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600,
                      color: AppColors.textSecondary)),
              const Spacer(),
              if (trailing != null) trailing,
            ],
          ),
          const Divider(height: 20),
          child,
        ],
      ),
    );
  }
}

// ── Dashboard activity row helper ─────────────────────────────────────────────

class _DashActivityRow extends StatelessWidget {
  final IconData icon;
  final String label;
  final Color color;
  const _DashActivityRow({required this.icon, required this.label, required this.color});

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Container(
          width: 26, height: 26,
          decoration: BoxDecoration(
            color: color.withOpacity(0.1),
            borderRadius: BorderRadius.circular(6),
          ),
          child: Icon(icon, color: color, size: 14),
        ),
        const SizedBox(width: 8),
        Text(label, style: const TextStyle(fontSize: 12, color: AppColors.textPrimary)),
      ],
    );
  }
}

// ── Share QR dialog ───────────────────────────────────────────────────────────

class _ShareQrDialog extends StatefulWidget {
  final CoreService coreService;
  final List<ShareAction> actions;

  const _ShareQrDialog({required this.coreService, required this.actions});

  @override
  State<_ShareQrDialog> createState() => _ShareQrDialogState();
}

class _ShareQrDialogState extends State<_ShareQrDialog> {
  ShareAction? _selectedAction;
  OobiResponse? _oobi;
  bool _loading = false;
  String? _error;
  bool _copied = false;

  @override
  void initState() {
    super.initState();
    final enabled = widget.actions.where((a) => a.isEnabled).toList();
    _selectedAction = enabled.isNotEmpty ? enabled.first
        : widget.actions.isNotEmpty ? widget.actions.first : null;
    if (_selectedAction != null) _fetchOobi(_selectedAction!.actionKey);
  }

  Future<void> _fetchOobi(String actionKey) async {
    setState(() { _loading = true; _error = null; _oobi = null; });
    try {
      final result = await widget.coreService.getOobi(action: actionKey);
      if (mounted) setState(() { _oobi = result; _loading = false; });
    } catch (e) {
      if (mounted) setState(() { _error = e.toString().split(': ').last; _loading = false; });
    }
  }

  void _onActionChanged(ShareAction? action) {
    if (action == null || !action.isEnabled) return;
    setState(() { _selectedAction = action; });
    _fetchOobi(action.actionKey);
  }

  void _copy() {
    if (_oobi == null) return;
    Clipboard.setData(ClipboardData(text: _oobi!.oobiUrl));
    setState(() => _copied = true);
    Future.delayed(const Duration(seconds: 2), () {
      if (mounted) setState(() => _copied = false);
    });
  }

  IconData _iconForKey(String key) {
    switch (key) {
      case 'add_contact': return Icons.person_add_outlined;
      case 'show_id': return Icons.badge_outlined;
      case 'request_payment': return Icons.payment_outlined;
      case 'share_file': return Icons.attach_file;
      case 'share_credential': return Icons.verified_outlined;
      default: return Icons.share_outlined;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Dialog(
      backgroundColor: AppColors.surface,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(16),
        side: const BorderSide(color: AppColors.border),
      ),
      child: SizedBox(
        width: 460,
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Header
              Row(
                children: [
                  const Icon(Icons.qr_code_outlined, color: AppColors.primary, size: 20),
                  const SizedBox(width: 10),
                  const Expanded(
                    child: Text('Share QR Code',
                        style: TextStyle(fontSize: 16, fontWeight: FontWeight.w700,
                            color: AppColors.textPrimary)),
                  ),
                  IconButton(
                    onPressed: () => Navigator.of(context).pop(),
                    icon: const Icon(Icons.close, size: 18, color: AppColors.textMuted),
                    padding: EdgeInsets.zero,
                    constraints: const BoxConstraints(),
                  ),
                ],
              ),
              const SizedBox(height: 16),
              // Action dropdown
              const Text('ACTION',
                  style: TextStyle(fontSize: 10, fontWeight: FontWeight.w600,
                      color: AppColors.textMuted, letterSpacing: 0.8)),
              const SizedBox(height: 6),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 12),
                decoration: BoxDecoration(
                  color: AppColors.surfaceLight,
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: AppColors.border),
                ),
                child: DropdownButtonHideUnderline(
                  child: DropdownButton<ShareAction>(
                    value: _selectedAction,
                    isExpanded: true,
                    dropdownColor: AppColors.surface,
                    style: const TextStyle(color: AppColors.textPrimary, fontSize: 13,
                        fontFamily: 'monospace'),
                    items: widget.actions.map((a) {
                      return DropdownMenuItem<ShareAction>(
                        value: a,
                        enabled: a.isEnabled,
                        child: Row(
                          children: [
                            Icon(_iconForKey(a.actionKey),
                                size: 16,
                                color: a.isEnabled ? AppColors.primary : AppColors.textMuted),
                            const SizedBox(width: 10),
                            Text(a.name,
                                style: TextStyle(
                                    color: a.isEnabled
                                        ? AppColors.textPrimary
                                        : AppColors.textMuted,
                                    fontSize: 13)),
                            if (!a.isEnabled) ...[
                              const SizedBox(width: 8),
                              Container(
                                padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
                                decoration: BoxDecoration(
                                  color: AppColors.border,
                                  borderRadius: BorderRadius.circular(3),
                                ),
                                child: const Text('Soon',
                                    style: TextStyle(fontSize: 9,
                                        color: AppColors.textMuted,
                                        fontWeight: FontWeight.w600)),
                              ),
                            ],
                          ],
                        ),
                      );
                    }).toList(),
                    onChanged: _onActionChanged,
                  ),
                ),
              ),
              if (_selectedAction != null) ...[
                const SizedBox(height: 8),
                Text(_selectedAction!.subtitle,
                    style: const TextStyle(color: AppColors.textSecondary,
                        fontSize: 12, height: 1.4)),
              ],
              const SizedBox(height: 20),
              // Body: loading / error / coming soon / QR
              if (_loading)
                const Center(
                  child: Padding(
                    padding: EdgeInsets.symmetric(vertical: 40),
                    child: CircularProgressIndicator(),
                  ),
                )
              else if (_error != null)
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: AppColors.error.withOpacity(0.08),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: AppColors.error.withOpacity(0.3)),
                  ),
                  child: Text(_error!,
                      style: const TextStyle(color: AppColors.error, fontSize: 12)),
                )
              else if (_selectedAction != null && !_selectedAction!.isEnabled)
                Container(
                  padding: const EdgeInsets.all(14),
                  decoration: BoxDecoration(
                    color: AppColors.surfaceLight,
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: AppColors.border),
                  ),
                  child: const Row(
                    children: [
                      Icon(Icons.schedule_outlined, color: AppColors.textMuted, size: 16),
                      SizedBox(width: 10),
                      Text('This action is coming soon.',
                          style: TextStyle(color: AppColors.textMuted, fontSize: 13)),
                    ],
                  ),
                )
              else if (_oobi != null) ...[
                // OOBI URL
                const Text('OOBI URL',
                    style: TextStyle(fontSize: 10, fontWeight: FontWeight.w600,
                        color: AppColors.textMuted, letterSpacing: 0.8)),
                const SizedBox(height: 6),
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: AppColors.surfaceLight,
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: AppColors.accent.withOpacity(0.3)),
                  ),
                  child: Row(
                    children: [
                      Expanded(
                        child: SelectableText(
                          _oobi!.oobiUrl,
                          style: const TextStyle(color: AppColors.accent, fontSize: 11,
                              fontFamily: 'monospace', height: 1.4),
                        ),
                      ),
                      const SizedBox(width: 8),
                      InkWell(
                        onTap: _copy,
                        borderRadius: BorderRadius.circular(6),
                        child: Container(
                          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
                          decoration: BoxDecoration(
                            color: _copied
                                ? AppColors.success.withOpacity(0.12)
                                : AppColors.surface,
                            borderRadius: BorderRadius.circular(6),
                            border: Border.all(
                                color: _copied
                                    ? AppColors.success.withOpacity(0.3)
                                    : AppColors.border),
                          ),
                          child: Row(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              Icon(_copied ? Icons.check : Icons.copy,
                                  color: _copied
                                      ? AppColors.success
                                      : AppColors.textSecondary,
                                  size: 13),
                              const SizedBox(width: 4),
                              Text(_copied ? 'COPIED' : 'COPY',
                                  style: TextStyle(
                                    color: _copied
                                        ? AppColors.success
                                        : AppColors.textSecondary,
                                    fontSize: 10,
                                    fontWeight: FontWeight.w600,
                                    letterSpacing: 1.0,
                                  )),
                            ],
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 20),
                // QR Code
                const Text('QR CODE',
                    style: TextStyle(fontSize: 10, fontWeight: FontWeight.w600,
                        color: AppColors.textMuted, letterSpacing: 0.8)),
                const SizedBox(height: 12),
                Center(
                  child: Container(
                    padding: const EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      color: Colors.white,
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: QrImageView(
                      data: _oobi!.oobiUrl,
                      version: QrVersions.auto,
                      size: 180,
                      backgroundColor: Colors.white,
                      eyeStyle: const QrEyeStyle(
                          eyeShape: QrEyeShape.square,
                          color: Color(0xFF0a0e1a)),
                      dataModuleStyle: const QrDataModuleStyle(
                          dataModuleShape: QrDataModuleShape.square,
                          color: Color(0xFF0a0e1a)),
                    ),
                  ),
                ),
              ],
              const SizedBox(height: 20),
              Align(
                alignment: Alignment.centerRight,
                child: ElevatedButton(
                  onPressed: () => Navigator.of(context).pop(),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: AppColors.primary,
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 10),
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                  ),
                  child: const Text('Done'),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
