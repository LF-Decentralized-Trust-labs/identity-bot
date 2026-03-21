import 'package:flutter/material.dart';
import '../theme/app_theme.dart';

class ConsentDetailItem {
  final String label;
  final String value;
  final bool isMonospace;
  final bool isSelectable;

  const ConsentDetailItem({
    required this.label,
    required this.value,
    this.isMonospace = true,
    this.isSelectable = false,
  });
}

class ConsentResult {
  final bool confirmed;
  final bool trusted;
  const ConsentResult({required this.confirmed, this.trusted = false});
}

class ConsentModal {
  static Future<ConsentResult?> show({
    required BuildContext context,
    required String title,
    String? subtitle,
    String? avatarLabel,
    String? name,
    List<ConsentDetailItem> details = const [],
    String confirmLabel = 'CONFIRM',
    String cancelLabel = 'CANCEL',
    Color? accentColor,
    IconData? icon,
    String? warningMessage,
    bool showAvatar = true,
    bool showTrustToggle = false,
  }) {
    final effectiveAccentColor = accentColor ?? AppColors.accent;
    final effectiveIcon = icon ?? Icons.verified_user_outlined;

    bool trusted = false;

    return showDialog<ConsentResult>(
      context: context,
      barrierDismissible: true,
      builder: (BuildContext context) {
        return StatefulBuilder(
          builder: (context, setInner) {
                return Dialog(
                  backgroundColor: Colors.transparent,
                  child: Container(
                    constraints: const BoxConstraints(maxWidth: 400),
                    decoration: BoxDecoration(
                      color: AppColors.surface,
                      border: Border.all(color: AppColors.border, width: 1),
                      borderRadius: BorderRadius.circular(16),
                    ),
                    child: SingleChildScrollView(
                      child: Padding(
                        padding: const EdgeInsets.all(24),
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            // Header
                            Row(
                              children: [
                                Icon(effectiveIcon,
                                    color: AppColors.textMuted, size: 20),
                                const SizedBox(width: 8),
                                Expanded(
                                  child: Column(
                                    crossAxisAlignment: CrossAxisAlignment.start,
                                    children: [
                                      Text(
                                        title.toUpperCase(),
                                        style: const TextStyle(
                                          color: AppColors.textMuted,
                                          fontSize: 11,
                                          fontWeight: FontWeight.w600,
                                          letterSpacing: 1.5,
                                          fontFamily: 'monospace',
                                        ),
                                      ),
                                      if (subtitle != null) ...[
                                        const SizedBox(height: 4),
                                        Text(
                                          subtitle,
                                          style: const TextStyle(
                                            color: AppColors.textSecondary,
                                            fontSize: 10,
                                            fontFamily: 'monospace',
                                          ),
                                        ),
                                      ],
                                    ],
                                  ),
                                ),
                              ],
                            ),
                            const SizedBox(height: 24),

                            // Avatar
                            if (showAvatar) ...[
                              Center(
                                child: Container(
                                  width: 50,
                                  height: 50,
                                  decoration: BoxDecoration(
                                    color:
                                        effectiveAccentColor.withOpacity(0.15),
                                    border: Border.all(
                                      color:
                                          effectiveAccentColor.withOpacity(0.3),
                                      width: 2,
                                    ),
                                    borderRadius: BorderRadius.circular(25),
                                  ),
                                  child: Center(
                                    child: avatarLabel != null
                                        ? Text(
                                            avatarLabel,
                                            style: TextStyle(
                                              color: effectiveAccentColor,
                                              fontSize: 20,
                                              fontWeight: FontWeight.w600,
                                              fontFamily: 'monospace',
                                            ),
                                          )
                                        : Icon(Icons.person,
                                            color: effectiveAccentColor,
                                            size: 24),
                                  ),
                                ),
                              ),
                              const SizedBox(height: 16),
                            ],

                            // Name
                            if (name != null) ...[
                              Text(
                                name,
                                style: const TextStyle(
                                  color: AppColors.textPrimary,
                                  fontSize: 16,
                                  fontWeight: FontWeight.w600,
                                  fontFamily: 'monospace',
                                ),
                                textAlign: TextAlign.center,
                              ),
                              const SizedBox(height: 20),
                            ],

                            // Details section
                            if (details.isNotEmpty) ...[
                              Container(
                                decoration: BoxDecoration(
                                  color: AppColors.surfaceLight,
                                  border: Border.all(
                                      color: AppColors.border, width: 1),
                                  borderRadius: BorderRadius.circular(8),
                                ),
                                child: Column(
                                  children: [
                                    for (int i = 0; i < details.length; i++) ...[
                                      Padding(
                                        padding: const EdgeInsets.all(12),
                                        child: Column(
                                          crossAxisAlignment:
                                              CrossAxisAlignment.start,
                                          children: [
                                            Text(
                                              details[i].label.toUpperCase(),
                                              style: const TextStyle(
                                                color: AppColors.textMuted,
                                                fontSize: 10,
                                                fontWeight: FontWeight.w600,
                                                letterSpacing: 1.0,
                                                fontFamily: 'monospace',
                                              ),
                                            ),
                                            const SizedBox(height: 6),
                                            details[i].isSelectable
                                                ? SelectableText(
                                                    details[i].value,
                                                    style: TextStyle(
                                                      color: details[i]
                                                              .isMonospace
                                                          ? effectiveAccentColor
                                                          : AppColors
                                                              .textPrimary,
                                                      fontSize: 11,
                                                      fontFamily: details[i]
                                                              .isMonospace
                                                          ? 'monospace'
                                                          : null,
                                                    ),
                                                  )
                                                : Text(
                                                    details[i].value,
                                                    style: TextStyle(
                                                      color: details[i]
                                                              .isMonospace
                                                          ? effectiveAccentColor
                                                          : AppColors
                                                              .textPrimary,
                                                      fontSize: 11,
                                                      fontFamily: details[i]
                                                              .isMonospace
                                                          ? 'monospace'
                                                          : null,
                                                    ),
                                                    overflow:
                                                        TextOverflow.ellipsis,
                                                    maxLines: 3,
                                                  ),
                                          ],
                                        ),
                                      ),
                                      if (i < details.length - 1)
                                        Divider(
                                          color: AppColors.border,
                                          height: 1,
                                          thickness: 1,
                                        ),
                                    ],
                                  ],
                                ),
                              ),
                              const SizedBox(height: 16),
                            ],

                            // Trust toggle — only shown when adding a contact
                            if (showTrustToggle) ...[
                              InkWell(
                                onTap: () => setInner(() => trusted = !trusted),
                                borderRadius: BorderRadius.circular(8),
                                child: Container(
                                  padding: const EdgeInsets.symmetric(
                                      horizontal: 12, vertical: 10),
                                  decoration: BoxDecoration(
                                    color: trusted
                                        ? AppColors.coreActive.withOpacity(0.08)
                                        : AppColors.surfaceLight,
                                    border: Border.all(
                                      color: trusted
                                          ? AppColors.coreActive
                                              .withOpacity(0.4)
                                          : AppColors.border,
                                    ),
                                    borderRadius: BorderRadius.circular(8),
                                  ),
                                  child: Row(
                                    children: [
                                      Checkbox(
                                        value: trusted,
                                        onChanged: (v) =>
                                            setInner(() => trusted = v!),
                                        activeColor: AppColors.coreActive,
                                        materialTapTargetSize:
                                            MaterialTapTargetSize.shrinkWrap,
                                        visualDensity: VisualDensity.compact,
                                      ),
                                      const SizedBox(width: 8),
                                      Expanded(
                                        child: Column(
                                          crossAxisAlignment:
                                              CrossAxisAlignment.start,
                                          children: [
                                            Text(
                                              'I know and trust this contact',
                                              style: TextStyle(
                                                color: trusted
                                                    ? AppColors.coreActive
                                                    : AppColors.textPrimary,
                                                fontSize: 13,
                                                fontWeight: FontWeight.w600,
                                              ),
                                            ),
                                            const SizedBox(height: 2),
                                            Text(
                                              'We have a prior relationship. '
                                              'They\'ll be added as your witness if you have capacity.',
                                              style: const TextStyle(
                                                color: AppColors.textSecondary,
                                                fontSize: 11,
                                              ),
                                            ),
                                          ],
                                        ),
                                      ),
                                    ],
                                  ),
                                ),
                              ),
                              const SizedBox(height: 16),
                            ],

                            // Warning message
                            if (warningMessage != null) ...[
                              Row(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Icon(Icons.warning_rounded,
                                      color: AppColors.corePending, size: 16),
                                  const SizedBox(width: 8),
                                  Expanded(
                                    child: Text(
                                      warningMessage,
                                      style: const TextStyle(
                                        color: AppColors.corePending,
                                        fontSize: 11,
                                        fontFamily: 'monospace',
                                      ),
                                    ),
                                  ),
                                ],
                              ),
                              const SizedBox(height: 20),
                            ],

                            // Buttons
                            Row(
                              children: [
                                Expanded(
                                  child: ElevatedButton(
                                    onPressed: () => Navigator.pop(
                                        context,
                                        const ConsentResult(
                                            confirmed: false)),
                                    style: ElevatedButton.styleFrom(
                                      backgroundColor: AppColors.surfaceLight,
                                      foregroundColor: AppColors.textSecondary,
                                      elevation: 0,
                                      padding: const EdgeInsets.symmetric(
                                          vertical: 12),
                                      shape: RoundedRectangleBorder(
                                        borderRadius: BorderRadius.circular(8),
                                      ),
                                    ),
                                    child: Text(
                                      cancelLabel.toUpperCase(),
                                      style: const TextStyle(
                                        fontSize: 12,
                                        fontWeight: FontWeight.w600,
                                        letterSpacing: 0.5,
                                        fontFamily: 'monospace',
                                      ),
                                    ),
                                  ),
                                ),
                                const SizedBox(width: 12),
                                Expanded(
                                  child: ElevatedButton(
                                    onPressed: () => Navigator.pop(
                                        context,
                                        ConsentResult(
                                            confirmed: true,
                                            trusted: trusted)),
                                    style: ElevatedButton.styleFrom(
                                      backgroundColor:
                                          effectiveAccentColor.withOpacity(0.15),
                                      foregroundColor: effectiveAccentColor,
                                      elevation: 0,
                                      padding: const EdgeInsets.symmetric(
                                          vertical: 12),
                                      side: BorderSide(
                                        color:
                                            effectiveAccentColor.withOpacity(0.3),
                                        width: 1,
                                      ),
                                      shape: RoundedRectangleBorder(
                                        borderRadius: BorderRadius.circular(8),
                                      ),
                                    ),
                                    child: Text(
                                      confirmLabel.toUpperCase(),
                                      style: const TextStyle(
                                        fontSize: 12,
                                        fontWeight: FontWeight.w600,
                                        letterSpacing: 0.5,
                                        fontFamily: 'monospace',
                                      ),
                                    ),
                                  ),
                                ),
                              ],
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),
                );
          },
        );
      },
    );
  }
}
