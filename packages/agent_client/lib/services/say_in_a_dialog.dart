import 'package:flutter/material.dart';

/// Tells the person something in a dialog with one OK button, and returns when
/// it is closed. The one copy both apps use to say what a log-out did or did
/// not do ([IdentityProfiles.logOutAndTell]). Does nothing when [context] is
/// no longer in the tree.
Future<void> sayInADialog(BuildContext context, String title, String body) async {
  if (!context.mounted) return;
  await showDialog<void>(
    context: context,
    builder: (c) => AlertDialog(
      title: Text(title),
      content: Text(body),
      actions: [
        TextButton(onPressed: () => Navigator.of(c).pop(), child: const Text('OK'))
      ],
    ),
  );
}
