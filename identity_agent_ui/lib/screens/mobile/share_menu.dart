import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:qr_flutter/qr_flutter.dart';
import '../../theme/mobile_theme.dart';
import '../../services/core_service.dart';
import '../../services/event_service.dart';
import '../../config/agent_config.dart';
import '../../widgets/contact_action_popup.dart';
import 'mobile_settings_screen.dart';

// Default action list — mirrors the seeded DB rows; used as a fallback if the
// API is unreachable so the Share menu is never empty.
const _defaultActions = [
  ShareAction(
    id: 'sa-add-contact',
    actionKey: 'add_contact',
    name: 'Add Contact',
    subtitle: 'Generate a shareable link so others can add you as a contact',
    icon: 'person_add_outlined',
    isEnabled: true,
    sortOrder: 1,
  ),
  ShareAction(
    id: 'sa-show-id',
    actionKey: 'show_id',
    name: 'Show ID',
    subtitle: 'Display your identity QR code',
    icon: 'badge_outlined',
    isEnabled: false,
    sortOrder: 2,
  ),
  ShareAction(
    id: 'sa-request-payment',
    actionKey: 'request_payment',
    name: 'Request Payment',
    subtitle: 'Send a payment request to a contact',
    icon: 'payment_outlined',
    isEnabled: false,
    sortOrder: 3,
  ),
  ShareAction(
    id: 'sa-share-file',
    actionKey: 'share_file',
    name: 'Share a File',
    subtitle: 'Send an encrypted file to a contact',
    icon: 'attach_file',
    isEnabled: false,
    sortOrder: 4,
  ),
  ShareAction(
    id: 'sa-share-credential',
    actionKey: 'share_credential',
    name: 'Share Credential',
    subtitle: 'Present a verifiable credential',
    icon: 'verified_outlined',
    isEnabled: false,
    sortOrder: 5,
  ),
];

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

class ShareMenu extends StatefulWidget {
  final String? serverUrl;
  final VoidCallback? onAddContactComplete;

  const ShareMenu({super.key, this.serverUrl, this.onAddContactComplete});

  @override
  State<ShareMenu> createState() => _ShareMenuState();
}

class _ShareMenuState extends State<ShareMenu> {
  late final CoreService _coreService =
      CoreService(baseUrl: widget.serverUrl ?? AgentConfig.coreBaseUrl);

  List<ShareAction> _actions = [];
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _loadActions();
  }

  @override
  void dispose() {
    _coreService.dispose();
    super.dispose();
  }

  Future<void> _loadActions() async {
    try {
      final actions = await _coreService.getShareActions();
      if (mounted) setState(() { _actions = actions; _loading = false; });
    } catch (_) {
      if (mounted) setState(() { _actions = _defaultActions; _loading = false; });
    }
  }

  void _handleTap(BuildContext context, ShareAction action) {
    if (!action.isEnabled) return;
    switch (action.actionKey) {
      case 'add_contact':
        Navigator.of(context).pop();
        Navigator.of(context).push(
          MaterialPageRoute(
            builder: (_) => _AddContactScreen(serverUrl: widget.serverUrl),
          ),
        ).then((_) => widget.onAddContactComplete?.call());
      default:
        _showComingSoon(context, action.name);
    }
  }

  void _showComingSoon(BuildContext context, String feature) {
    Navigator.of(context).pop();
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Coming Soon'),
        content: Text('$feature will be available in a future update.'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('OK'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: const BoxDecoration(
        color: MobileColors.surface,
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const SizedBox(height: 8),
          Container(
            width: 40,
            height: 4,
            decoration: BoxDecoration(
              color: MobileColors.surfaceTertiary,
              borderRadius: BorderRadius.circular(2),
            ),
          ),
          const SizedBox(height: 16),
          const Text(
            'Share',
            style: TextStyle(
              fontSize: 18,
              fontWeight: FontWeight.w700,
              color: MobileColors.textPrimary,
            ),
          ),
          const SizedBox(height: 8),
          if (_loading)
            const Padding(
              padding: EdgeInsets.symmetric(vertical: 24),
              child: CircularProgressIndicator(color: MobileColors.primary),
            )
          else
            ..._actions.map((action) => _ShareItem(
              icon: _iconForKey(action.actionKey),
              label: action.name,
              subtitle: action.subtitle,
              isActive: action.isEnabled,
              onTap: () => _handleTap(context, action),
            )),
          SizedBox(height: MediaQuery.of(context).padding.bottom + 12),
        ],
      ),
    );
  }
}

class _ShareItem extends StatelessWidget {
  final IconData icon;
  final String label;
  final String subtitle;
  final VoidCallback onTap;
  final bool isActive;

  const _ShareItem({
    required this.icon,
    required this.label,
    required this.subtitle,
    required this.onTap,
    this.isActive = false,
  });

  @override
  Widget build(BuildContext context) {
    return ListTile(
      leading: Container(
        width: 40,
        height: 40,
        decoration: BoxDecoration(
          color: MobileColors.primary.withOpacity(0.1),
          borderRadius: BorderRadius.circular(10),
        ),
        child: Icon(icon, color: MobileColors.primary, size: 22),
      ),
      title: Text(
        label,
        style: const TextStyle(
          fontSize: 15,
          fontWeight: FontWeight.w600,
          color: MobileColors.textPrimary,
        ),
      ),
      subtitle: Text(
        subtitle,
        style: const TextStyle(
          fontSize: 12,
          color: MobileColors.textMuted,
        ),
      ),
      trailing: isActive
          ? null
          : Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
              decoration: BoxDecoration(
                color: MobileColors.surfaceTertiary,
                borderRadius: BorderRadius.circular(4),
              ),
              child: const Text(
                'Soon',
                style: TextStyle(
                  fontSize: 10,
                  color: MobileColors.textMuted,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ),
      onTap: onTap,
      contentPadding: const EdgeInsets.symmetric(horizontal: 20, vertical: 2),
    );
  }
}

class _AddContactScreen extends StatefulWidget {
  final String? serverUrl;

  const _AddContactScreen({this.serverUrl});

  @override
  State<_AddContactScreen> createState() => _AddContactScreenState();
}

class _AddContactScreenState extends State<_AddContactScreen> {
  late final CoreService _coreService =
      CoreService(baseUrl: widget.serverUrl ?? AgentConfig.coreBaseUrl);
  late final EventService _eventService =
      EventService.instance(widget.serverUrl ?? AgentConfig.coreBaseUrl);

  StreamSubscription<AgentEvent>? _eventSub;
  OverlayEntry? _popupOverlay;

  bool _loading = true;
  String? _error;
  OobiResponse? _oobi;
  bool _copied = false;

  @override
  void initState() {
    super.initState();
    _loadOobi();
    _listenForEvents();
  }

  @override
  void dispose() {
    _eventSub?.cancel();
    _dismissPopup();
    _coreService.dispose();
    super.dispose();
  }

  void _listenForEvents() {
    debugPrint('[AddContactScreen] *** Subscribing to EventService events (connected=${_eventService.isConnected})');
    _eventSub = _eventService.events.listen((event) {
      debugPrint('[AddContactScreen] *** Event received on QR screen: ${event.type} | alias="${event.senderAlias}"');
      if (!mounted) {
        debugPrint('[AddContactScreen] *** Widget not mounted, ignoring event');
        return;
      }
      if (event.type == 'introduction_received') {
        debugPrint('[AddContactScreen] *** Showing connection popup for: ${event.senderDisplayName}');
        _showConnectionPopup(event.senderDisplayName, event.senderAid, event.senderPhoto);
      }
    });
  }

  void _showConnectionPopup(String name, String aid, String photo) {
    _dismissPopup();

    final overlay = Overlay.of(context);
    _popupOverlay = OverlayEntry(
      builder: (ctx) => ContactActionPopup(
        name: name.isNotEmpty ? name : (aid.length > 12 ? '${aid.substring(0, 12)}...' : aid),
        photo: photo,
        aid: aid,
        intentLabel: 'Wants to add you as a contact',
        confirmLabel: 'Add Contact',
        dismissLabel: 'Dismiss',
        onConfirm: () {
          _acceptContact(aid);
          _dismissPopup();
        },
        onDismiss: () {
          _rejectContact(aid);
          _dismissPopup();
        },
        onBackdropTap: _dismissPopup,
      ),
    );
    overlay.insert(_popupOverlay!);
  }

  Future<void> _acceptContact(String aid) async {
    try {
      await _coreService.acceptContact(aid);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Contact accepted'),
            backgroundColor: MobileColors.success,
          ),
        );
      }
    } catch (e) {
      debugPrint('[AddContactScreen] Accept failed: $e');
    }
  }

  Future<void> _rejectContact(String aid) async {
    try {
      await _coreService.rejectContact(aid);
    } catch (e) {
      debugPrint('[AddContactScreen] Reject failed: $e');
    }
  }

  void _dismissPopup() {
    _popupOverlay?.remove();
    _popupOverlay = null;
  }

  Future<void> _loadOobi() async {
    setState(() {
      _loading = true;
      _error = null;
    });

    try {
      final result = await _coreService.getOobi(action: 'add_contact');

      if (!result.tunnelActive || result.endpointUrl.isEmpty) {
        if (mounted) {
          setState(() => _loading = false);
          _showNoTunnelDialog();
        }
        return;
      }

      setState(() {
        _oobi = result;
        _loading = false;
      });
    } catch (e) {
      setState(() {
        _error = e.toString();
        _loading = false;
      });
    }
  }

  void _showNoTunnelDialog() {
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => AlertDialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: Row(
          children: [
            Container(
              width: 36,
              height: 36,
              decoration: BoxDecoration(
                color: MobileColors.warning.withOpacity(0.15),
                borderRadius: BorderRadius.circular(8),
              ),
              child: const Icon(Icons.wifi_off,
                  color: MobileColors.warning, size: 20),
            ),
            const SizedBox(width: 12),
            const Expanded(
              child: Text(
                'No Public Link',
                style: TextStyle(
                  color: MobileColors.textPrimary,
                  fontWeight: FontWeight.w700,
                  fontSize: 18,
                ),
              ),
            ),
          ],
        ),
        content: const Text(
          'You need to configure a tunnel provider to generate a shareable link. '
          'Go to Settings to set up your public URL.',
          style: TextStyle(
            color: MobileColors.textSecondary,
            fontSize: 14,
            height: 1.5,
          ),
        ),
        actions: [
          TextButton(
            onPressed: () {
              Navigator.of(ctx).pop();
              Navigator.of(context).pop();
            },
            child: const Text(
              'Cancel',
              style: TextStyle(color: MobileColors.textMuted),
            ),
          ),
          ElevatedButton(
            onPressed: () {
              Navigator.of(ctx).pop();
              Navigator.of(context).pushReplacement(
                MaterialPageRoute(
                  builder: (_) =>
                      MobileSettingsScreen(serverUrl: widget.serverUrl),
                ),
              );
            },
            style: ElevatedButton.styleFrom(
              backgroundColor: MobileColors.primary,
              foregroundColor: MobileColors.textOnPrimary,
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(8)),
            ),
            child: const Text('Go to Settings'),
          ),
        ],
      ),
    );
  }

  void _copyToClipboard() {
    if (_oobi == null) return;
    Clipboard.setData(ClipboardData(text: _oobi!.oobiUrl));
    setState(() => _copied = true);
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('OOBI link copied to clipboard'),
        behavior: SnackBarBehavior.floating,
        duration: Duration(seconds: 2),
      ),
    );
    Future.delayed(const Duration(seconds: 2), () {
      if (mounted) setState(() => _copied = false);
    });
  }

  @override
  Widget build(BuildContext context) {
    return Theme(
      data: MobileTheme.lightTheme,
      child: Scaffold(
        backgroundColor: MobileColors.background,
        appBar: AppBar(
          backgroundColor: MobileColors.surface,
          elevation: 0,
          leading: IconButton(
            icon: const Icon(Icons.arrow_back,
                color: MobileColors.textPrimary),
            onPressed: () => Navigator.of(context).pop(),
          ),
          title: const Text(
            'Add Contact',
            style: TextStyle(
              color: MobileColors.textPrimary,
              fontSize: 18,
              fontWeight: FontWeight.w600,
            ),
          ),
          centerTitle: true,
          actions: [
            if (_oobi != null)
              IconButton(
                icon: const Icon(Icons.refresh, color: MobileColors.primary),
                onPressed: _loadOobi,
              ),
          ],
          bottom: PreferredSize(
            preferredSize: const Size.fromHeight(1),
            child: Container(color: MobileColors.border, height: 1),
          ),
        ),
        body: _loading
            ? const Center(
                child:
                    CircularProgressIndicator(color: MobileColors.primary))
            : _error != null
                ? _buildError()
                : _oobi != null
                    ? _buildOobiContent()
                    : const SizedBox.shrink(),
      ),
    );
  }

  Widget _buildError() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.error_outline,
                size: 48, color: MobileColors.error),
            const SizedBox(height: 16),
            Text(
              _error ?? 'An error occurred',
              style: const TextStyle(
                color: MobileColors.textSecondary,
                fontSize: 14,
              ),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 24),
            OutlinedButton.icon(
              onPressed: _loadOobi,
              icon: const Icon(Icons.refresh, size: 18),
              label: const Text('Retry'),
              style: OutlinedButton.styleFrom(
                foregroundColor: MobileColors.primary,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildOobiContent() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(20),
      child: Column(
        children: [
          _buildStatusBanner(),
          const SizedBox(height: 24),
          _buildQrCard(),
          const SizedBox(height: 20),
          _buildUrlCard(),
          const SizedBox(height: 24),
          _buildCopyButton(),
          const SizedBox(height: 24),
          _buildHelpText(),
          const SizedBox(height: 32),
        ],
      ),
    );
  }

  Widget _buildStatusBanner() {
    final source = _oobi!.endpointSource;
    final isTunnel = source.startsWith('tunnel:');
    final providerName = isTunnel ? source.replaceFirst('tunnel:', '') : source;

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      decoration: BoxDecoration(
        color: MobileColors.success.withOpacity(0.08),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: MobileColors.success.withOpacity(0.3)),
      ),
      child: Row(
        children: [
          Container(
            width: 8,
            height: 8,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: MobileColors.success,
              boxShadow: [
                BoxShadow(
                    color: MobileColors.success.withOpacity(0.4),
                    blurRadius: 4)
              ],
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              isTunnel
                  ? 'Tunnel active via ${providerName.toUpperCase()}'
                  : 'Connected via $providerName',
              style: const TextStyle(
                color: MobileColors.success,
                fontSize: 13,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildQrCard() {
    return Container(
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        color: MobileColors.surface,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: MobileColors.border),
        boxShadow: [
          BoxShadow(
            color: MobileColors.cardShadow,
            blurRadius: 12,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: Column(
        children: [
          const Text(
            'Scan to connect',
            style: TextStyle(
              color: MobileColors.textSecondary,
              fontSize: 14,
              fontWeight: FontWeight.w500,
            ),
          ),
          const SizedBox(height: 16),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: Colors.white,
              borderRadius: BorderRadius.circular(12),
            ),
            child: QrImageView(
              data: _oobi!.oobiUrl,
              version: QrVersions.auto,
              size: 200,
              backgroundColor: Colors.white,
              eyeStyle: const QrEyeStyle(
                eyeShape: QrEyeShape.square,
                color: MobileColors.textPrimary,
              ),
              dataModuleStyle: const QrDataModuleStyle(
                dataModuleShape: QrDataModuleShape.square,
                color: MobileColors.textPrimary,
              ),
            ),
          ),
          const SizedBox(height: 16),
          Text(
            _oobi!.aid,
            style: const TextStyle(
              color: MobileColors.textMuted,
              fontSize: 11,
              fontFamily: 'monospace',
            ),
            textAlign: TextAlign.center,
            maxLines: 2,
            overflow: TextOverflow.ellipsis,
          ),
        ],
      ),
    );
  }

  Widget _buildUrlCard() {
    return GestureDetector(
      onTap: _copyToClipboard,
      child: Container(
        width: double.infinity,
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: MobileColors.surfaceSecondary,
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: MobileColors.border),
        ),
        child: Row(
          children: [
            const Icon(Icons.link, size: 18, color: MobileColors.primary),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                _oobi!.oobiUrl,
                style: const TextStyle(
                  color: MobileColors.primary,
                  fontSize: 13,
                  fontFamily: 'monospace',
                ),
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
              ),
            ),
            const SizedBox(width: 8),
            Icon(
              _copied ? Icons.check : Icons.copy,
              size: 16,
              color: _copied ? MobileColors.success : MobileColors.textMuted,
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildCopyButton() {
    return SizedBox(
      width: double.infinity,
      child: ElevatedButton.icon(
        onPressed: _copyToClipboard,
        icon: Icon(_copied ? Icons.check : Icons.copy, size: 18),
        label: Text(_copied ? 'Copied!' : 'Copy Link'),
        style: ElevatedButton.styleFrom(
          backgroundColor: MobileColors.primary,
          foregroundColor: MobileColors.textOnPrimary,
          padding: const EdgeInsets.symmetric(vertical: 14),
          shape:
              RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
        ),
      ),
    );
  }

  Widget _buildHelpText() {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: MobileColors.info.withOpacity(0.06),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: MobileColors.info.withOpacity(0.15)),
      ),
      child: const Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(Icons.info_outline, size: 18, color: MobileColors.info),
          SizedBox(width: 10),
          Expanded(
            child: Text(
              'Share this link or QR code with anyone you want to connect with. '
              'They can use it to discover your identity and send you a connection request.',
              style: TextStyle(
                color: MobileColors.textSecondary,
                fontSize: 13,
                height: 1.5,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
