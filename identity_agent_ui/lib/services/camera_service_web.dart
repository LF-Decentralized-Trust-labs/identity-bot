import 'dart:html' as html;

Future<bool> detectCamera() async {
  try {
    final devices =
        await html.window.navigator.mediaDevices!.enumerateDevices();
    return devices.any((d) => d.kind == 'videoinput');
  } catch (_) {
    return false;
  }
}
