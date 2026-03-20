# Suppress R8 warnings for Android 14+ back gesture API referenced by
# flutter_inappwebview but not present in the compile-time classpath.
-dontwarn android.window.**
