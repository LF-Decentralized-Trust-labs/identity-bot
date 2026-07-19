import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:agent_client/services/core_service.dart';
import '../theme/app_theme.dart';

/// Shows a detail modal for an alert item. Displays full contact info for
/// connection requests, or full credential details for incoming credentials.
/// Returns the chosen action: 'accept', 'reject', 'dismiss', or null (closed).
class AlertDetailModal {
  /// Show details for an incoming contact request.
  static Future<String?> showContactDetail(
    BuildContext context, {
    required ContactResponse contact,
  }) {
    return showDialog<String>(
      context: context,
      barrierDismissible: true,
      builder: (_) => _ContactDetailDialog(contact: contact),
    );
  }

  /// Show details for an incoming credential.
  static Future<String?> showCredentialDetail(
    BuildContext context, {
    required CredentialRecord credential,
  }) {
    return showDialog<String>(
      context: context,
      barrierDismissible: true,
      builder: (_) => _CredentialDetailDialog(credential: credential),
    );
  }

  /// Show details for a pending (failed) request.
  static Future<String?> showPendingDetail(
    BuildContext context, {
    required PendingRequestResponse request,
  }) {
    return showDialog<String>(
      context: context,
      barrierDismissible: true,
      builder: (_) => _PendingDetailDialog(request: request),
    );
  }
}

// ── Contact detail ────────────────────────────────────────────────────────────

class _ContactDetailDialog extends StatelessWidget {
  final ContactResponse contact;
  const _ContactDetailDialog({required this.contact});

  @override
  Widget build(BuildContext context) {
    return Dialog(
      backgroundColor: AppColors.surface,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 440),
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Header
              Row(
                children: [
                  CircleAvatar(
                    radius: 22,
                    backgroundColor: AppColors.primary.withOpacity(0.12),
                    backgroundImage: contact.photo.isNotEmpty
                        ? MemoryImage(base64Decode(
                            contact.photo.contains(',')
                                ? contact.photo.split(',').last
                                : contact.photo))
                        : null,
                    child: contact.photo.isEmpty
                        ? Text(
                            contact.displayName.isNotEmpty
                                ? contact.displayName[0].toUpperCase()
                                : '?',
                            style: const TextStyle(
                              color: AppColors.primary,
                              fontWeight: FontWeight.w700,
                              fontSize: 16,
                            ),
                          )
                        : null,
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          contact.displayName,
                          style: const TextStyle(
                            fontSize: 18,
                            fontWeight: FontWeight.w700,
                            color: AppColors.textPrimary,
                          ),
                        ),
                        const SizedBox(height: 2),
                        const Text(
                          'Connection Request',
                          style: TextStyle(
                            fontSize: 12,
                            color: AppColors.textMuted,
                          ),
                        ),
                      ],
                    ),
                  ),
                  IconButton(
                    onPressed: () => Navigator.pop(context),
                    icon: const Icon(Icons.close, size: 20),
                    color: AppColors.textMuted,
                    padding: EdgeInsets.zero,
                    constraints: const BoxConstraints(),
                  ),
                ],
              ),
              const SizedBox(height: 20),
              const Divider(color: AppColors.border, height: 1),
              const SizedBox(height: 16),
              // Details
              _detailRow('AID', contact.aid, monospace: true, copyable: true, context: context),
              if (contact.alias.isNotEmpty)
                _detailRow('Alias', contact.alias, context: context),
              if (contact.oobiUrl.isNotEmpty)
                _detailRow('OOBI URL', contact.oobiUrl, monospace: true, copyable: true, context: context),
              if (contact.contactType.isNotEmpty)
                _detailRow('Contact Type', contact.contactType, context: context),
              _detailRow('Status', contact.status, context: context),
              if (contact.discoveredAt.isNotEmpty)
                _detailRow('Discovered', contact.discoveredAt, context: context),
              const SizedBox(height: 20),
              // Actions
              Row(
                mainAxisAlignment: MainAxisAlignment.end,
                children: [
                  TextButton(
                    onPressed: () => Navigator.pop(context, 'reject'),
                    style: TextButton.styleFrom(foregroundColor: AppColors.error),
                    child: const Text('Reject'),
                  ),
                  const SizedBox(width: 8),
                  ElevatedButton(
                    onPressed: () => Navigator.pop(context, 'accept'),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: AppColors.success,
                      foregroundColor: Colors.white,
                      elevation: 0,
                    ),
                    child: const Text('Accept'),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}

// ── Credential detail ─────────────────────────────────────────────────────────

class _CredentialDetailDialog extends StatelessWidget {
  final CredentialRecord credential;
  const _CredentialDetailDialog({required this.credential});

  @override
  Widget build(BuildContext context) {
    final typeDisplay = credential.credentialType.isNotEmpty
        ? credential.credentialType
        : 'Credential';
    final issuerDisplay = credential.issuerName.isNotEmpty
        ? credential.issuerName
        : credential.issuerAid;

    // Try to parse ACDC JSON for attribute display
    Map<String, dynamic>? acdcAttrs;
    if (credential.acdcJson.isNotEmpty) {
      try {
        final acdc = jsonDecode(credential.acdcJson) as Map<String, dynamic>;
        acdcAttrs = acdc['a'] as Map<String, dynamic>?;
      } catch (_) {}
    }

    return Dialog(
      backgroundColor: AppColors.surface,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 480),
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Header
              Row(
                children: [
                  Container(
                    width: 44,
                    height: 44,
                    decoration: BoxDecoration(
                      color: AppColors.success.withOpacity(0.12),
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: const Icon(Icons.verified_outlined, color: AppColors.success, size: 24),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          typeDisplay,
                          style: const TextStyle(
                            fontSize: 18,
                            fontWeight: FontWeight.w700,
                            color: AppColors.textPrimary,
                          ),
                        ),
                        const SizedBox(height: 2),
                        Text(
                          'From $issuerDisplay',
                          style: const TextStyle(fontSize: 12, color: AppColors.textMuted),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ],
                    ),
                  ),
                  IconButton(
                    onPressed: () => Navigator.pop(context),
                    icon: const Icon(Icons.close, size: 20),
                    color: AppColors.textMuted,
                    padding: EdgeInsets.zero,
                    constraints: const BoxConstraints(),
                  ),
                ],
              ),
              const SizedBox(height: 20),
              const Divider(color: AppColors.border, height: 1),
              const SizedBox(height: 16),
              // Details
              _detailRow('SAID', credential.said, monospace: true, copyable: true, context: context),
              _detailRow('Issuer AID', credential.issuerAid, monospace: true, copyable: true, context: context),
              if (credential.holderAid.isNotEmpty)
                _detailRow('Holder AID', credential.holderAid, monospace: true, copyable: true, context: context),
              if (credential.format.isNotEmpty)
                _detailRow('Format', credential.format.toUpperCase(), context: context),
              if (credential.issuedAt.isNotEmpty)
                _detailRow('Issued', credential.issuedAt, context: context),
              if (credential.expiryDate.isNotEmpty)
                _detailRow('Expires', credential.expiryDate, context: context),
              // Show ACDC attributes if available
              if (acdcAttrs != null && acdcAttrs.isNotEmpty) ...[
                const SizedBox(height: 8),
                const Text('Attributes', style: TextStyle(
                  fontSize: 13, fontWeight: FontWeight.w600, color: AppColors.textSecondary)),
                const SizedBox(height: 8),
                ...acdcAttrs.entries
                    .where((e) => e.key != 'd' && e.key != 'i')
                    .map((e) => _detailRow(
                          _formatKey(e.key),
                          e.value?.toString() ?? '',
                          context: context,
                        )),
              ],
              const SizedBox(height: 20),
              // Actions
              Row(
                mainAxisAlignment: MainAxisAlignment.end,
                children: [
                  TextButton(
                    onPressed: () => Navigator.pop(context, 'reject'),
                    style: TextButton.styleFrom(foregroundColor: AppColors.error),
                    child: const Text('Reject'),
                  ),
                  const SizedBox(width: 8),
                  ElevatedButton(
                    onPressed: () => Navigator.pop(context, 'accept'),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: AppColors.success,
                      foregroundColor: Colors.white,
                      elevation: 0,
                    ),
                    child: const Text('Accept'),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  String _formatKey(String key) {
    return key.replaceAll('_', ' ').split(' ')
        .map((w) => w.isEmpty ? '' : '${w[0].toUpperCase()}${w.substring(1)}')
        .join(' ');
  }
}

// ── Pending request detail ────────────────────────────────────────────────────

class _PendingDetailDialog extends StatelessWidget {
  final PendingRequestResponse request;
  const _PendingDetailDialog({required this.request});

  @override
  Widget build(BuildContext context) {
    return Dialog(
      backgroundColor: AppColors.surface,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 440),
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Header
              Row(
                children: [
                  Container(
                    width: 44,
                    height: 44,
                    decoration: BoxDecoration(
                      color: AppColors.error.withOpacity(0.12),
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: const Icon(Icons.link_off, color: AppColors.error, size: 24),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          request.displayName,
                          style: const TextStyle(
                            fontSize: 18,
                            fontWeight: FontWeight.w700,
                            color: AppColors.textPrimary,
                          ),
                        ),
                        const SizedBox(height: 2),
                        const Text(
                          'Failed Request',
                          style: TextStyle(fontSize: 12, color: AppColors.error),
                        ),
                      ],
                    ),
                  ),
                  IconButton(
                    onPressed: () => Navigator.pop(context),
                    icon: const Icon(Icons.close, size: 20),
                    color: AppColors.textMuted,
                    padding: EdgeInsets.zero,
                    constraints: const BoxConstraints(),
                  ),
                ],
              ),
              const SizedBox(height: 20),
              const Divider(color: AppColors.border, height: 1),
              const SizedBox(height: 16),
              _detailRow('AID', request.aid, monospace: true, copyable: true, context: context),
              if (request.oobiUrl.isNotEmpty)
                _detailRow('OOBI URL', request.oobiUrl, monospace: true, copyable: true, context: context),
              if (request.errorReason.isNotEmpty)
                _detailRow('Error', request.errorReason, context: context),
              if (request.receivedAt.isNotEmpty)
                _detailRow('Received', request.receivedAt, context: context),
              if (request.expiresAt.isNotEmpty)
                _detailRow('Expires', request.expiresAt, context: context),
              const SizedBox(height: 20),
              Row(
                mainAxisAlignment: MainAxisAlignment.end,
                children: [
                  ElevatedButton(
                    onPressed: () => Navigator.pop(context, 'dismiss'),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: AppColors.textMuted,
                      foregroundColor: Colors.white,
                      elevation: 0,
                    ),
                    child: const Text('Dismiss'),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}

// ── Shared detail row ─────────────────────────────────────────────────────────

Widget _detailRow(
  String label,
  String value, {
  bool monospace = false,
  bool copyable = false,
  required BuildContext context,
}) {
  if (value.isEmpty) return const SizedBox.shrink();
  return Padding(
    padding: const EdgeInsets.only(bottom: 10),
    child: Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          width: 110,
          child: Text(
            label,
            style: const TextStyle(
              fontSize: 12,
              fontWeight: FontWeight.w600,
              color: AppColors.textMuted,
            ),
          ),
        ),
        Expanded(
          child: SelectableText(
            value,
            style: TextStyle(
              fontSize: 12,
              color: AppColors.textPrimary,
              fontFamily: monospace ? 'monospace' : null,
            ),
            maxLines: 3,
          ),
        ),
        if (copyable)
          InkWell(
            onTap: () {
              Clipboard.setData(ClipboardData(text: value));
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(
                  content: Text('$label copied'),
                  duration: const Duration(seconds: 1),
                ),
              );
            },
            child: const Padding(
              padding: EdgeInsets.only(left: 4),
              child: Icon(Icons.copy, size: 14, color: AppColors.textMuted),
            ),
          ),
      ],
    ),
  );
}
