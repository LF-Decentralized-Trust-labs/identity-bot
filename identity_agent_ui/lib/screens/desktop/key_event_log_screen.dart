import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;
import '../../theme/app_theme.dart';
import 'package:agent_client/config/agent_config.dart';
import 'package:agent_client/services/core_service.dart';

class KeyEventLogScreen extends StatefulWidget {
  final String? serverUrl;
  const KeyEventLogScreen({super.key, this.serverUrl});

  @override
  State<KeyEventLogScreen> createState() => _KeyEventLogScreenState();
}

class _KeyEventLogScreenState extends State<KeyEventLogScreen> {
  String get _baseUrl => widget.serverUrl ?? AgentConfig.coreBaseUrl;

  List<Map<String, dynamic>> _events = [];
  String? _aid;
  bool _loading = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() { _loading = true; _error = null; });
    try {
      final coreService = CoreService(baseUrl: _baseUrl);
      final identity = await coreService.getIdentity();
      coreService.dispose();

      if (!identity.initialized || identity.aid == null) {
        setState(() { _error = 'No identity found.'; _loading = false; });
        return;
      }

      final aid = identity.aid!;
      final uri = Uri.parse('$_baseUrl/api/kel').replace(queryParameters: {'name': aid});
      final resp = await http.get(uri);
      if (resp.statusCode != 200) {
        setState(() { _error = 'Server returned ${resp.statusCode}'; _loading = false; });
        return;
      }
      final body = json.decode(resp.body) as Map<String, dynamic>;
      final kel = (body['kel'] as List? ?? []).cast<Map<String, dynamic>>();
      setState(() {
        _aid = aid;
        _events = kel;
        _loading = false;
      });
    } catch (e) {
      setState(() { _error = e.toString(); _loading = false; });
    }
  }

  String _eventType(Map<String, dynamic> ev) {
    final t = ev['t'] as String? ?? ev['type'] as String? ?? '?';
    return t.toUpperCase();
  }

  Color _badgeColor(String type) {
    switch (type) {
      case 'ICP': return AppColors.primary;
      case 'ROT': return AppColors.warning;
      case 'IXN': return AppColors.success;
      default:    return AppColors.textMuted;
    }
  }

  String _eventLabel(String type) {
    switch (type) {
      case 'ICP': return 'Inception';
      case 'ROT': return 'Rotation';
      case 'IXN': return 'Interaction';
      default:    return type;
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Scaffold(
      backgroundColor: cs.surface,
      body: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _buildHeader(context),
          const Divider(height: 1),
          if (_loading)
            const Expanded(child: Center(child: CircularProgressIndicator()))
          else if (_error != null)
            Expanded(child: Center(child: Text(_error!, style: const TextStyle(color: AppColors.error))))
          else if (_events.isEmpty)
            Expanded(child: Center(child: Text('No events found.', style: TextStyle(color: AppColors.textMuted))))
          else
            Expanded(child: _buildTable(context)),
        ],
      ),
    );
  }

  Widget _buildHeader(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(32, 32, 32, 20),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Key Event Log', style: Theme.of(context).textTheme.headlineMedium),
                const SizedBox(height: 4),
                if (_aid != null)
                  Text(
                    _aid!.length > 60 ? '${_aid!.substring(0, 60)}…' : _aid!,
                    style: TextStyle(fontSize: 12, color: AppColors.textMuted, fontFamily: 'monospace'),
                  ),
              ],
            ),
          ),
          Text(
            '${_events.length} event${_events.length == 1 ? '' : 's'}',
            style: TextStyle(color: AppColors.textMuted, fontSize: 13),
          ),
          const SizedBox(width: 16),
          IconButton(
            onPressed: _load,
            icon: const Icon(Icons.refresh),
            tooltip: 'Refresh',
            color: AppColors.textSecondary,
          ),
        ],
      ),
    );
  }

  Widget _buildTable(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.fromLTRB(32, 0, 32, 32),
      child: Container(
        decoration: BoxDecoration(
          border: Border.all(color: AppColors.border),
          borderRadius: BorderRadius.circular(12),
          color: Theme.of(context).colorScheme.surface,
        ),
        child: Column(
          children: [
            _buildTableHeader(),
            const Divider(height: 1),
            ..._events.asMap().entries.map((entry) {
              return Column(
                children: [
                  _buildTableRow(context, entry.value, entry.key),
                  if (entry.key < _events.length - 1)
                    Divider(height: 1, color: AppColors.border.withOpacity(0.5)),
                ],
              );
            }),
          ],
        ),
      ),
    );
  }

  Widget _buildTableHeader() {
    const style = TextStyle(
      fontSize: 11,
      fontWeight: FontWeight.w600,
      color: AppColors.textMuted,
      letterSpacing: 0.5,
    );
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
      color: AppColors.background,
      child: const Row(
        children: [
          SizedBox(width: 40, child: Text('#', style: style)),
          SizedBox(width: 80, child: Text('TYPE', style: style)),
          SizedBox(width: 120, child: Text('EVENT', style: style)),
          Expanded(child: Text('DIGEST / IDENTIFIER', style: style)),
          SizedBox(width: 80, child: Text('SEQ', style: style, textAlign: TextAlign.right)),
        ],
      ),
    );
  }

  Widget _buildTableRow(BuildContext context, Map<String, dynamic> ev, int index) {
    final type = _eventType(ev);
    final seq = ev['s'] ?? ev['seq'] ?? index;
    final digest = ev['d'] as String? ?? ev['digest'] as String? ?? '-';
    final badgeColor = _badgeColor(type);

    return InkWell(
      onTap: () => _showEventDetail(context, ev),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
        child: Row(
          children: [
            SizedBox(
              width: 40,
              child: Text('${index + 1}', style: TextStyle(color: AppColors.textMuted, fontSize: 13)),
            ),
            SizedBox(
              width: 80,
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                  color: badgeColor.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(4),
                  border: Border.all(color: badgeColor.withOpacity(0.3)),
                ),
                child: Text(
                  type,
                  style: TextStyle(fontSize: 11, fontWeight: FontWeight.w700, color: badgeColor, fontFamily: 'monospace'),
                  textAlign: TextAlign.center,
                ),
              ),
            ),
            SizedBox(
              width: 120,
              child: Text(_eventLabel(type), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w500, color: AppColors.textPrimary)),
            ),
            Expanded(
              child: Text(
                digest.length > 48 ? '${digest.substring(0, 48)}…' : digest,
                style: TextStyle(fontSize: 12, color: AppColors.textMuted, fontFamily: 'monospace'),
              ),
            ),
            SizedBox(
              width: 80,
              child: Text('$seq', style: const TextStyle(fontSize: 13, color: AppColors.textSecondary), textAlign: TextAlign.right),
            ),
          ],
        ),
      ),
    );
  }

  void _showEventDetail(BuildContext context, Map<String, dynamic> ev) {
    final pretty = const JsonEncoder.withIndent('  ').convert(ev);
    showDialog(
      context: context,
      builder: (_) => AlertDialog(
        title: Text('Event Detail — ${_eventType(ev)}'),
        content: SizedBox(
          width: 560,
          child: SingleChildScrollView(
            child: SelectableText(
              pretty,
              style: const TextStyle(fontSize: 12, fontFamily: 'monospace'),
            ),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () {
              Clipboard.setData(ClipboardData(text: pretty));
              Navigator.of(context).pop();
            },
            child: const Text('Copy JSON'),
          ),
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }
}
