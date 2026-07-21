import 'dart:io' show Platform;

bool isMobilePlatform() => Platform.isAndroid || Platform.isIOS;
