import 'dart:async';

import 'package:flutter/material.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../services/core_service.dart';
import '../theme/app_theme.dart';

/// Who this identity answers to, and bringing somebody else in.
///
/// The whole ceremony happens with everybody in the room. Each incoming owner
/// gets their own code, scans it from their own device, and their agent sends
/// back a public key — no key material ever crosses the screen or the wire.
///
/// Nothing here is specific to one kind of identity. A guardianship passing to
/// somebody else and a person spreading control of their own identity so
/// recovery does not rest on a single key are the same operation.
///
/// The screen's one job is to make the waiting legible. An ownership change
/// takes as long as the slowest person's phone, and during that time it must be
/// obvious who has done their part and who has not — otherwise somebody stares
/// at a spinner wondering whether it worked, and taps things.
class OwnersScreen extends StatefulWidget {
  const OwnersScreen({super.key, required this.coreService});

  final CoreService coreService;

  @override
  State<OwnersScreen> createState() => _OwnersScreenState();
}

class _OwnersScreenState extends State<OwnersScreen> {
  IdentityOwners? _owners;
  OwnerCeremony? _ceremony;
  String _error = '';
  bool _loading = true;
  bool _busy = false;
  Timer? _poll;

  @override
  void initState() {
    super.initState();
    _refresh();
    // Each acceptance arrives on somebody else's device, so this screen only
    // learns about it by asking. Two seconds is fast enough that a scan feels
    // acknowledged and slow enough not to hammer the agent.
    _poll = Timer.periodic(const Duration(seconds: 2), (_) => _refresh(quiet: true));
  }

  @override
  void dispose() {
    _poll?.cancel();
    super.dispose();
  }

  Future<void> _refresh({bool quiet = false}) async {
    try {
      final owners = await widget.coreService.getOwners();
      final ceremony = await widget.coreService.getOwnerCeremony();
      if (!mounted) return;
      setState(() {
        _owners = owners;
        _ceremony = ceremony;
        _loading = false;
        if (!quiet) _error = '';
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _loading = false;
        // A failed poll is not worth shouting about — the next one is two
        // seconds away. A failed deliberate action is.
        if (!quiet) _error = e.toString();
      });
    }
  }

  Future<void> _start(List<String> names) async {
    setState(() {
      _busy = true;
      _error = '';
    });
    try {
      final ceremony = await widget.coreService.startOwnerCeremony(names);
      if (!mounted) return;
      setState(() => _ceremony = ceremony);
    } catch (e) {
      if (!mounted) return;
      setState(() => _error = e.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _abandon() async {
    setState(() => _busy = true);
    try {
      await widget.coreService.abandonOwnerCeremony();
      await _refresh();
    } catch (e) {
      if (mounted) setState(() => _error = e.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const Center(child: CircularProgressIndicator(color: AppColors.primary));
    }

    return SingleChildScrollView(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (_error.isNotEmpty) _errorBanner(),
          _ownersCard(),
          const SizedBox(height: 16),
          if (_ceremony != null && _ceremony!.isCollecting)
            _collectingCard(_ceremony!)
          else if (_ceremony != null && _ceremony!.hasFailed)
            _failedCard(_ceremony!)
          else
            _startCard(),
        ],
      ),
    );
  }

  Widget _errorBanner() => Container(
        margin: const EdgeInsets.only(bottom: 16),
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: AppColors.error.withOpacity(0.1),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: AppColors.error.withOpacity(0.3)),
        ),
        child: Text(_error,
            style: const TextStyle(color: AppColors.error, fontSize: 12, height: 1.4)),
      );

  Widget _ownersCard() {
    final owners = _owners?.owners ?? const <String>[];
    return _card(
      title: 'Owners',
      subtitle: owners.length == 1
          ? 'One party controls this identity.'
          : '${owners.length} parties control this identity.',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          for (final aid in owners)
            Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: Row(children: [
                const Icon(Icons.verified_user_outlined, size: 16, color: AppColors.primary),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(aid,
                      style: const TextStyle(
                          color: AppColors.textPrimary, fontSize: 12, fontFamily: 'monospace'),
                      overflow: TextOverflow.ellipsis),
                ),
              ]),
            ),
          const SizedBox(height: 4),
          const Text(
            'Read from this identity’s own key event log, so it is the same '
            'answer anybody outside this machine would get.',
            style: TextStyle(color: AppColors.textMuted, fontSize: 11, height: 1.4),
          ),
        ],
      ),
    );
  }

  Widget _startCard() => _card(
        title: 'Bring somebody in',
        subtitle:
            'The identity keeps working throughout. Nothing changes until everybody '
            'invited has scanned their code.',
        child: _InviteForm(busy: _busy, onStart: _start),
      );

  Widget _collectingCard(OwnerCeremony ceremony) {
    final outstanding = ceremony.outstanding.length;
    return _card(
      title: 'Waiting for ${outstanding == 0 ? 'the rotation' : '$outstanding to scan'}',
      subtitle: outstanding == 0
          ? 'Everybody has scanned. Applying the change.'
          : 'Each person scans their own code, from their own device. Their key never '
              'leaves it — only the public half is sent.',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          for (final invitee in ceremony.invited) ...[
            _InviteeTile(invitee: invitee),
            const SizedBox(height: 20),
          ],
          Align(
            alignment: Alignment.centerLeft,
            child: TextButton(
              onPressed: _busy ? null : _abandon,
              child: const Text('Abandon this ceremony',
                  style: TextStyle(color: AppColors.textMuted, fontSize: 12)),
            ),
          ),
        ],
      ),
    );
  }

  Widget _failedCard(OwnerCeremony ceremony) => _card(
        title: 'The ownership change did not complete',
        subtitle: ceremony.detail.isEmpty
            ? 'No reason was recorded.'
            : ceremony.detail,
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          const Text(
            'Control is unchanged. Everybody who scanned will need to scan again.',
            style: TextStyle(color: AppColors.textSecondary, fontSize: 12, height: 1.4),
          ),
          const SizedBox(height: 12),
          _InviteForm(busy: _busy, onStart: _start, label: 'Try again'),
        ]),
      );

  Widget _card({required String title, required String subtitle, required Widget child}) =>
      Container(
        width: double.infinity,
        padding: const EdgeInsets.all(18),
        decoration: BoxDecoration(
          color: AppColors.surface,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: AppColors.surfaceVariant),
        ),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(title,
              style: const TextStyle(
                  color: AppColors.textPrimary, fontSize: 15, fontWeight: FontWeight.w600)),
          const SizedBox(height: 4),
          Text(subtitle,
              style: const TextStyle(color: AppColors.textSecondary, fontSize: 12, height: 1.4)),
          const SizedBox(height: 16),
          child,
        ]),
      );
}

/// One person's code, and whether they have used it.
///
/// The code disappears once they accept. Leaving it on screen would invite a
/// second scan, and somebody scanning a code that has already been spent gets
/// no feedback that anything happened — they would reasonably conclude it had
/// not worked.
class _InviteeTile extends StatelessWidget {
  const _InviteeTile({required this.invitee});

  final CeremonyInvitee invitee;

  @override
  Widget build(BuildContext context) {
    if (invitee.accepted) {
      return Row(children: [
        const Icon(Icons.check_circle, size: 18, color: AppColors.success),
        const SizedBox(width: 8),
        Text(invitee.name,
            style: const TextStyle(
                color: AppColors.textPrimary, fontSize: 13, fontWeight: FontWeight.w600)),
        const SizedBox(width: 8),
        const Text('accepted',
            style: TextStyle(color: AppColors.textMuted, fontSize: 12)),
      ]);
    }

    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Row(children: [
        const SizedBox(
          width: 18,
          height: 18,
          child: CircularProgressIndicator(strokeWidth: 2, color: AppColors.textMuted),
        ),
        const SizedBox(width: 8),
        Text(invitee.name,
            style: const TextStyle(
                color: AppColors.textPrimary, fontSize: 13, fontWeight: FontWeight.w600)),
        const SizedBox(width: 8),
        const Text('has not scanned yet',
            style: TextStyle(color: AppColors.textMuted, fontSize: 12)),
      ]),
      const SizedBox(height: 10),
      Center(
        child: Container(
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
            color: Colors.white,
            borderRadius: BorderRadius.circular(12),
          ),
          child: QrImageView(
            data: invitee.inviteUrl,
            version: QrVersions.auto,
            size: 180,
            backgroundColor: Colors.white,
            eyeStyle: const QrEyeStyle(
              eyeShape: QrEyeShape.square,
              color: AppColors.textPrimary,
            ),
            dataModuleStyle: const QrDataModuleStyle(
              dataModuleShape: QrDataModuleShape.square,
              color: AppColors.textPrimary,
            ),
          ),
        ),
      ),
    ]);
  }
}

/// Naming the people being brought in.
///
/// The names are for the person running the ceremony to tell one code from
/// another. Nothing cryptographic depends on them, and the screen says so
/// rather than implying the name is being recorded as an identity.
class _InviteForm extends StatefulWidget {
  const _InviteForm({required this.busy, required this.onStart, this.label = 'Create the codes'});

  final bool busy;
  final void Function(List<String>) onStart;
  final String label;

  @override
  State<_InviteForm> createState() => _InviteFormState();
}

class _InviteFormState extends State<_InviteForm> {
  final List<TextEditingController> _names = [TextEditingController()];

  @override
  void dispose() {
    for (final c in _names) {
      c.dispose();
    }
    super.dispose();
  }

  List<String> get _filled =>
      _names.map((c) => c.text.trim()).where((n) => n.isNotEmpty).toList();

  @override
  Widget build(BuildContext context) {
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      for (var i = 0; i < _names.length; i++)
        Padding(
          padding: const EdgeInsets.only(bottom: 10),
          child: TextField(
            controller: _names[i],
            onChanged: (_) => setState(() {}),
            style: const TextStyle(color: AppColors.textPrimary, fontSize: 13),
            decoration: InputDecoration(
              hintText: 'Name of the ${i == 0 ? 'first' : 'next'} person',
              hintStyle: const TextStyle(color: AppColors.textMuted, fontSize: 13),
              isDense: true,
              contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 12),
              border: OutlineInputBorder(borderRadius: BorderRadius.circular(8)),
            ),
          ),
        ),
      Row(children: [
        TextButton.icon(
          onPressed: widget.busy
              ? null
              : () => setState(() => _names.add(TextEditingController())),
          icon: const Icon(Icons.add, size: 16),
          label: const Text('Add another', style: TextStyle(fontSize: 12)),
        ),
        const Spacer(),
        ElevatedButton(
          onPressed: widget.busy || _filled.isEmpty
              ? null
              : () => widget.onStart(_filled),
          child: Text(widget.busy ? 'Working…' : widget.label),
        ),
      ]),
      const SizedBox(height: 6),
      const Text(
        'Names are only so you can tell one code from another. Each person’s '
        'identity comes from their own device when they scan.',
        style: TextStyle(color: AppColors.textMuted, fontSize: 11, height: 1.4),
      ),
    ]);
  }
}
