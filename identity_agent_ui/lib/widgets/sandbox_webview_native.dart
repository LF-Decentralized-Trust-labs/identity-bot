import 'dart:io' show Platform, Process, ProcessResult;
import 'package:flutter/foundation.dart' show kIsWeb, debugPrint;
import 'package:flutter/material.dart';
import 'package:flutter_inappwebview_platform_interface/flutter_inappwebview_platform_interface.dart'
    show
        InAppWebViewPlatform,
        InAppWebViewSettings,
        NavigationActionPolicy,
        PlatformInAppWebViewController,
        PlatformInAppWebViewWidgetCreationParams,
        ServerTrustAuthResponse,
        ServerTrustAuthResponseAction,
        URLRequest,
        WebUri;
import 'package:url_launcher/url_launcher.dart';
import '../theme/app_theme.dart';

bool get _isDesktopPlatform {
  if (kIsWeb) return false;
  try {
    return Platform.isWindows || Platform.isMacOS || Platform.isLinux;
  } catch (_) {
    return false;
  }
}

Future<bool> _checkWebKitGtkAvailable() async {
  if (kIsWeb || !Platform.isLinux) return true;
  try {
    final result = await Process.run('pkg-config', ['--exists', 'webkit2gtk-4.1']);
    if (result.exitCode == 0) return true;
    final result40 = await Process.run('pkg-config', ['--exists', 'webkit2gtk-4.0']);
    return result40.exitCode == 0;
  } catch (_) {
    try {
      final result = await Process.run('ldconfig', ['-p']);
      final output = (result as ProcessResult).stdout as String;
      return output.contains('libwebkit2gtk');
    } catch (_) {
      return false;
    }
  }
}

enum SandboxWebViewStatus {
  loading,
  ready,
  error,
  unsupported,
  missingWebKitGtk,
}

class SandboxWebView extends StatefulWidget {
  final String url;
  final String appName;
  final VoidCallback? onClose;
  final void Function(String url)? onNavigationBlocked;

  const SandboxWebView({
    super.key,
    required this.url,
    required this.appName,
    this.onClose,
    this.onNavigationBlocked,
  });

  @override
  State<SandboxWebView> createState() => _SandboxWebViewState();
}

class _SandboxWebViewState extends State<SandboxWebView> {
  PlatformInAppWebViewController? _controller;
  SandboxWebViewStatus _status = SandboxWebViewStatus.loading;
  String? _errorMessage;
  double _progress = 0.0;
  String _currentUrl = '';
  bool _webKitGtkChecked = false;

  @override
  void initState() {
    super.initState();
    _currentUrl = widget.url;
    _checkPlatformSupport();
  }

  Future<void> _checkPlatformSupport() async {
    if (!_isDesktopPlatform) {
      setState(() {
        _status = SandboxWebViewStatus.unsupported;
        _errorMessage = 'Sandbox WebView is only available on desktop platforms.';
      });
      return;
    }

    if (!kIsWeb && Platform.isLinux) {
      final available = await _checkWebKitGtkAvailable();
      _webKitGtkChecked = true;
      if (!available) {
        setState(() {
          _status = SandboxWebViewStatus.missingWebKitGtk;
          _errorMessage =
              'Install WebKitGTK for in-app display.\n\n'
              'Ubuntu/Debian: sudo apt install libwebkit2gtk-4.1-dev\n'
              'Fedora: sudo dnf install webkit2gtk4.1-devel\n'
              'Arch: sudo pacman -S webkit2gtk-4.1';
        });
        return;
      }
    }

    setState(() => _status = SandboxWebViewStatus.loading);
  }

  bool _isAllowedNavigation(String targetUrl) {
    try {
      final uri = Uri.parse(targetUrl);
      if (uri.scheme == 'file') return false;
      if (uri.scheme == 'javascript') return false;
      if (uri.scheme == 'data') return false;
      final baseUri = Uri.parse(widget.url);
      if (uri.host == baseUri.host) return true;
      if (uri.host == 'localhost' || uri.host == '127.0.0.1') return true;
      if (uri.host == 'agent.internal') return true;
      return false;
    } catch (_) {
      return false;
    }
  }

  InAppWebViewSettings get _secureSettings => InAppWebViewSettings(
        javaScriptEnabled: true,
        allowFileAccessFromFileURLs: false,
        allowUniversalAccessFromFileURLs: false,
        javaScriptCanOpenWindowsAutomatically: false,
        mediaPlaybackRequiresUserGesture: true,
        transparentBackground: false,
        useShouldOverrideUrlLoading: true,
        useOnLoadResource: false,
        allowsBackForwardNavigationGestures: false,
        disableDefaultErrorPage: true,
      );

  Future<void> _openInBrowser() async {
    final uri = Uri.parse(widget.url);
    try {
      await launchUrl(uri, mode: LaunchMode.externalApplication);
    } catch (e) {
      debugPrint('[SandboxWebView] Failed to open browser: $e');
    }
  }

  void _reload() {
    _controller?.reload();
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        _buildToolbar(),
        if (_status == SandboxWebViewStatus.loading && _progress > 0 && _progress < 1.0)
          LinearProgressIndicator(
            value: _progress,
            backgroundColor: AppColors.surface,
            valueColor: const AlwaysStoppedAnimation<Color>(AppColors.accent),
            minHeight: 2,
          ),
        Expanded(child: _buildContent()),
      ],
    );
  }

  Widget _buildToolbar() {
    return Container(
      height: 40,
      padding: const EdgeInsets.symmetric(horizontal: 8),
      decoration: const BoxDecoration(
        color: AppColors.surface,
        border: Border(
          bottom: BorderSide(color: AppColors.border, width: 1),
        ),
      ),
      child: Row(
        children: [
          Container(
            width: 10,
            height: 10,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: _status == SandboxWebViewStatus.ready
                  ? AppColors.coreActive
                  : _status == SandboxWebViewStatus.loading
                      ? AppColors.corePending
                      : AppColors.coreInactive,
            ),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              widget.appName,
              style: const TextStyle(
                color: AppColors.textPrimary,
                fontSize: 12,
                fontWeight: FontWeight.w600,
                fontFamily: 'monospace',
                letterSpacing: 0.5,
              ),
              overflow: TextOverflow.ellipsis,
            ),
          ),
          if (_status == SandboxWebViewStatus.ready ||
              _status == SandboxWebViewStatus.error)
            IconButton(
              icon: const Icon(Icons.refresh, size: 16),
              color: AppColors.textSecondary,
              padding: EdgeInsets.zero,
              constraints: const BoxConstraints(minWidth: 32, minHeight: 32),
              onPressed: _reload,
              tooltip: 'Reload',
            ),
          IconButton(
            icon: const Icon(Icons.open_in_browser, size: 16),
            color: AppColors.textSecondary,
            padding: EdgeInsets.zero,
            constraints: const BoxConstraints(minWidth: 32, minHeight: 32),
            onPressed: _openInBrowser,
            tooltip: 'Open in browser',
          ),
          if (widget.onClose != null)
            IconButton(
              icon: const Icon(Icons.close, size: 16),
              color: AppColors.textSecondary,
              padding: EdgeInsets.zero,
              constraints: const BoxConstraints(minWidth: 32, minHeight: 32),
              onPressed: widget.onClose,
              tooltip: 'Close',
            ),
        ],
      ),
    );
  }

  Widget _buildContent() {
    if (_status == SandboxWebViewStatus.unsupported ||
        _status == SandboxWebViewStatus.missingWebKitGtk) {
      return _buildFallbackView();
    }

    // Use the platform_interface factory directly (avoids flutter_inappwebview
    // meta-package which registers a web plugin that crashes Flutter web).
    final webviewWidget = InAppWebViewPlatform.instance!
        .createPlatformInAppWebViewWidget(
          PlatformInAppWebViewWidgetCreationParams(
            initialUrlRequest: URLRequest(url: WebUri(widget.url)),
            initialSettings: _secureSettings,
            onWebViewCreated: (controller) {
              _controller = controller;
            },
            onLoadStart: (controller, url) {
              setState(() {
                _status = SandboxWebViewStatus.loading;
                if (url != null) _currentUrl = url.toString();
              });
            },
            onLoadStop: (controller, url) {
              setState(() {
                _status = SandboxWebViewStatus.ready;
                _progress = 1.0;
                if (url != null) _currentUrl = url.toString();
              });
            },
            onReceivedError: (controller, request, error) {
              debugPrint('[SandboxWebView] Load error: ${error.description}');
              setState(() {
                _status = SandboxWebViewStatus.error;
                _errorMessage = error.description;
              });
            },
            onProgressChanged: (controller, progress) {
              setState(() => _progress = progress / 100.0);
            },
            shouldOverrideUrlLoading: (controller, navigationAction) async {
              final url = navigationAction.request.url?.toString() ?? '';
              if (!_isAllowedNavigation(url)) {
                debugPrint('[SandboxWebView] Blocked navigation to: $url');
                widget.onNavigationBlocked?.call(url);
                return NavigationActionPolicy.CANCEL;
              }
              return NavigationActionPolicy.ALLOW;
            },
            onConsoleMessage: (controller, consoleMessage) {
              debugPrint('[SandboxWebView][Console] ${consoleMessage.message}');
            },
            onReceivedServerTrustAuthRequest: (controller, challenge) async {
              return ServerTrustAuthResponse(
                action: ServerTrustAuthResponseAction.PROCEED,
              );
            },
          ),
        )
        .build(context);

    return Stack(
      children: [
        webviewWidget,
        if (_status == SandboxWebViewStatus.error) _buildErrorOverlay(),
      ],
    );
  }

  Widget _buildErrorOverlay() {
    return Container(
      color: AppColors.primary.withOpacity(0.9),
      child: Center(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(
                Icons.error_outline,
                color: AppColors.error,
                size: 48,
              ),
              const SizedBox(height: 16),
              const Text(
                'FAILED TO LOAD',
                style: TextStyle(
                  color: AppColors.textPrimary,
                  fontSize: 16,
                  fontWeight: FontWeight.w700,
                  fontFamily: 'monospace',
                  letterSpacing: 1.5,
                ),
              ),
              const SizedBox(height: 8),
              Text(
                _errorMessage ?? 'Unknown error',
                style: const TextStyle(
                  color: AppColors.textSecondary,
                  fontSize: 12,
                  fontFamily: 'monospace',
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 24),
              Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  _buildActionButton(
                    icon: Icons.refresh,
                    label: 'RETRY',
                    onPressed: _reload,
                  ),
                  const SizedBox(width: 12),
                  _buildActionButton(
                    icon: Icons.open_in_browser,
                    label: 'OPEN IN BROWSER',
                    onPressed: _openInBrowser,
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildFallbackView() {
    final isMissingWebKit = _status == SandboxWebViewStatus.missingWebKitGtk;

    return Container(
      color: AppColors.primary,
      child: Center(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(
                isMissingWebKit ? Icons.warning_amber : Icons.desktop_access_disabled,
                color: isMissingWebKit ? AppColors.warning : AppColors.textMuted,
                size: 48,
              ),
              const SizedBox(height: 16),
              Text(
                isMissingWebKit ? 'WEBKITGTK REQUIRED' : 'UNSUPPORTED PLATFORM',
                style: const TextStyle(
                  color: AppColors.textPrimary,
                  fontSize: 16,
                  fontWeight: FontWeight.w700,
                  fontFamily: 'monospace',
                  letterSpacing: 1.5,
                ),
              ),
              const SizedBox(height: 12),
              Text(
                _errorMessage ?? 'WebView is not available on this platform.',
                style: const TextStyle(
                  color: AppColors.textSecondary,
                  fontSize: 12,
                  fontFamily: 'monospace',
                  height: 1.6,
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 24),
              _buildActionButton(
                icon: Icons.open_in_browser,
                label: 'OPEN IN BROWSER',
                onPressed: _openInBrowser,
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildActionButton({
    required IconData icon,
    required String label,
    required VoidCallback onPressed,
  }) {
    return OutlinedButton.icon(
      onPressed: onPressed,
      icon: Icon(icon, size: 16),
      label: Text(
        label,
        style: const TextStyle(
          fontSize: 11,
          fontFamily: 'monospace',
          letterSpacing: 1.0,
        ),
      ),
      style: OutlinedButton.styleFrom(
        foregroundColor: AppColors.accent,
        side: const BorderSide(color: AppColors.accent, width: 1),
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(4),
        ),
      ),
    );
  }
}
