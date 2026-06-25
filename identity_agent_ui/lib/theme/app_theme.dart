import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../brand/brand.dart';

// ── Unified color tokens ──────────────────────────────────────────────────────
// Light theme values are the canonical source of truth.
// The dark theme overrides backgrounds and text via ThemeData; screens that
// use Theme.of(context).colorScheme will automatically adapt.
class AppColors {
  // Brand blue (IBM Carbon 60)
  static const Color primary       = Color(0xFF4589FF);
  static const Color primaryLight  = Color(0xFF78A9FF);
  static const Color primaryDark   = Color(0xFF0F62FE);

  // Light theme backgrounds
  static const Color background    = Color(0xFFF4F4F4);
  static const Color surface       = Color(0xFFFFFFFF);
  static const Color surfaceLight  = Color(0xFFF8F9FA);
  static const Color surfaceVariant= Color(0xFFE8E8E8);

  // Light theme text
  static const Color textPrimary   = Color(0xFF161616);
  static const Color textSecondary = Color(0xFF525252);
  static const Color textMuted     = Color(0xFF8D8D8D);

  // Borders / dividers
  static const Color border        = Color(0xFFE0E0E0);

  // Semantic / accent aliases (kept for back-compat with existing screens)
  static const Color accent        = Color(0xFF4589FF);
  static const Color accentDim     = Color(0xFF78A9FF);
  static const Color success       = Color(0xFF24A148);
  static const Color warning       = Color(0xFFF1C21B);
  static const Color error         = Color(0xFFDA1E28);

  // Status aliases used by older screens
  static const Color coreActive    = Color(0xFF24A148);
  static const Color coreInactive  = Color(0xFFDA1E28);
  static const Color corePending   = Color(0xFFF1C21B);
}

// ── Layout breakpoint helper ─────────────────────────────────────────────────
// Single source of truth for mobile vs desktop layout decisions.
// Uses screen width so mobile layouts can be tested in a browser by resizing.
// For hardware-only checks (NFC, Rust FFI, ports), use Platform directly.
class AppLayout {
  static const double mobileBreakpoint = 768;

  /// True when the screen should show mobile layout — either on a native
  /// mobile platform or when the window is narrower than [mobileBreakpoint].
  static bool isMobile(BuildContext context) {
    return MediaQuery.of(context).size.width < mobileBreakpoint;
  }
}

// ── Theme notifier (global singleton) ────────────────────────────────────────
class ThemeNotifier {
  static const String _prefKey = 'app_theme_mode';

  static final ValueNotifier<ThemeMode> instance =
      ValueNotifier<ThemeMode>(ThemeMode.light);

  /// Call once at app startup, before runApp.
  static Future<void> initialize() async {
    final prefs = await SharedPreferences.getInstance();
    final saved = prefs.getString(_prefKey);
    instance.value = (saved == 'dark') ? ThemeMode.dark : ThemeMode.light;
  }

  static Future<void> setMode(ThemeMode mode) async {
    instance.value = mode;
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_prefKey, mode == ThemeMode.dark ? 'dark' : 'light');
  }

  static bool get isDark => instance.value == ThemeMode.dark;
}

// ── Theme definitions ─────────────────────────────────────────────────────────
class AppTheme {
  // ─── Light theme ───────────────────────────────────────────────────────────
  static ThemeData get light {
    return ThemeData(
      brightness: Brightness.light,
      scaffoldBackgroundColor: AppColors.background,
      colorScheme: ColorScheme.light(
        primary:                    currentBrand.primary,
        secondary:                  currentBrand.primaryLight,
        surface:                    AppColors.surface,
        error:                      AppColors.error,
        onPrimary:                  Colors.white,
        onSecondary:                Colors.white,
        onSurface:                  AppColors.textPrimary,
        onError:                    Colors.white,
        outline:                    AppColors.border,
        outlineVariant:             Color(0xFFF0F0F0),
        surfaceContainerHighest:    AppColors.surfaceVariant,
      ),
      fontFamily: 'sans-serif',
      textTheme: const TextTheme(
        headlineLarge:  TextStyle(color: AppColors.textPrimary,   fontSize: 28, fontWeight: FontWeight.w700, letterSpacing: -0.5),
        headlineMedium: TextStyle(color: AppColors.textPrimary,   fontSize: 22, fontWeight: FontWeight.w600),
        titleLarge:     TextStyle(color: AppColors.textPrimary,   fontSize: 18, fontWeight: FontWeight.w600),
        titleMedium:    TextStyle(color: AppColors.textSecondary, fontSize: 16, fontWeight: FontWeight.w500),
        bodyLarge:      TextStyle(color: AppColors.textPrimary,   fontSize: 16),
        bodyMedium:     TextStyle(color: AppColors.textSecondary, fontSize: 14),
        bodySmall:      TextStyle(color: AppColors.textMuted,     fontSize: 12),
        labelLarge:     TextStyle(color: AppColors.primary,       fontSize: 14, fontWeight: FontWeight.w600),
        labelSmall:     TextStyle(color: AppColors.textMuted,     fontSize: 11, fontWeight: FontWeight.w500, letterSpacing: 0.5),
      ),
      appBarTheme: const AppBarTheme(
        backgroundColor:  AppColors.surface,
        foregroundColor:  AppColors.textPrimary,
        elevation:        0,
        scrolledUnderElevation: 0,
        titleTextStyle:   TextStyle(color: AppColors.textPrimary, fontSize: 18, fontWeight: FontWeight.w600),
      ),
      cardTheme: CardThemeData(
        color:     AppColors.surface,
        elevation: 0,
        shape:     RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
          side:         const BorderSide(color: AppColors.border),
        ),
        margin: EdgeInsets.zero,
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: AppColors.primary,
          foregroundColor: Colors.white,
          elevation:       0,
          padding:         const EdgeInsets.symmetric(horizontal: 24, vertical: 14),
          shape:           RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
          textStyle:       const TextStyle(fontSize: 14, fontWeight: FontWeight.w600),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: AppColors.primary,
          side:            const BorderSide(color: AppColors.primary),
          padding:         const EdgeInsets.symmetric(horizontal: 24, vertical: 14),
          shape:           RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
          textStyle:       const TextStyle(fontSize: 14, fontWeight: FontWeight.w600),
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled:      true,
        fillColor:   AppColors.surfaceLight,
        border:         OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: const BorderSide(color: AppColors.border)),
        enabledBorder:  OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: const BorderSide(color: AppColors.border)),
        focusedBorder:  OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: const BorderSide(color: AppColors.primary, width: 2)),
        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
        labelStyle:     const TextStyle(color: AppColors.textSecondary),
        hintStyle:      const TextStyle(color: AppColors.textMuted),
      ),
      dividerTheme: const DividerThemeData(color: AppColors.border, thickness: 1, space: 1),
      chipTheme: ChipThemeData(
        backgroundColor: AppColors.surfaceVariant,
        labelStyle: const TextStyle(color: AppColors.textSecondary, fontSize: 12),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6)),
      ),
      useMaterial3: true,
    );
  }

  // ─── Standard dark theme (NOT cyberpunk) ──────────────────────────────────
  static ThemeData get dark {
    const darkBg          = Color(0xFF111111);
    const darkSurface     = Color(0xFF1C1C1C);
    const darkSurfaceVar  = Color(0xFF2A2A2A);
    const darkBorder      = Color(0xFF333333);
    const darkText        = Color(0xFFE8E8E8);
    const darkTextSec     = Color(0xFF9E9E9E);
    const darkTextMuted   = Color(0xFF616161);

    return ThemeData(
      brightness: Brightness.dark,
      scaffoldBackgroundColor: darkBg,
      colorScheme: ColorScheme.dark(
        primary:                    currentBrand.primary,
        secondary:                  currentBrand.primaryLight,
        surface:                    darkSurface,
        error:                      AppColors.error,
        onPrimary:                  Colors.white,
        onSecondary:                Colors.white,
        onSurface:                  darkText,
        onError:                    Colors.white,
        outline:                    darkBorder,
        outlineVariant:             Color(0xFF222222),
        surfaceContainerHighest:    darkSurfaceVar,
      ),
      fontFamily: 'sans-serif',
      textTheme: const TextTheme(
        headlineLarge:  TextStyle(color: darkText,      fontSize: 28, fontWeight: FontWeight.w700, letterSpacing: -0.5),
        headlineMedium: TextStyle(color: darkText,      fontSize: 22, fontWeight: FontWeight.w600),
        titleLarge:     TextStyle(color: darkText,      fontSize: 18, fontWeight: FontWeight.w600),
        titleMedium:    TextStyle(color: darkTextSec,   fontSize: 16, fontWeight: FontWeight.w500),
        bodyLarge:      TextStyle(color: darkText,      fontSize: 16),
        bodyMedium:     TextStyle(color: darkTextSec,   fontSize: 14),
        bodySmall:      TextStyle(color: darkTextMuted, fontSize: 12),
        labelLarge:     TextStyle(color: AppColors.primary, fontSize: 14, fontWeight: FontWeight.w600),
        labelSmall:     TextStyle(color: darkTextMuted, fontSize: 11, fontWeight: FontWeight.w500, letterSpacing: 0.5),
      ),
      appBarTheme: const AppBarTheme(
        backgroundColor:  darkSurface,
        foregroundColor:  darkText,
        elevation:        0,
        scrolledUnderElevation: 0,
        titleTextStyle:   TextStyle(color: darkText, fontSize: 18, fontWeight: FontWeight.w600),
      ),
      cardTheme: CardThemeData(
        color:     darkSurface,
        elevation: 0,
        shape:     RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
          side:         const BorderSide(color: darkBorder),
        ),
        margin: EdgeInsets.zero,
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: AppColors.primary,
          foregroundColor: Colors.white,
          elevation:       0,
          padding:         const EdgeInsets.symmetric(horizontal: 24, vertical: 14),
          shape:           RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
          textStyle:       const TextStyle(fontSize: 14, fontWeight: FontWeight.w600),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: AppColors.primary,
          side:            const BorderSide(color: AppColors.primary),
          padding:         const EdgeInsets.symmetric(horizontal: 24, vertical: 14),
          shape:           RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
          textStyle:       const TextStyle(fontSize: 14, fontWeight: FontWeight.w600),
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled:      true,
        fillColor:   darkSurfaceVar,
        border:         OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: const BorderSide(color: darkBorder)),
        enabledBorder:  OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: const BorderSide(color: darkBorder)),
        focusedBorder:  OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: const BorderSide(color: AppColors.primary, width: 2)),
        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
        labelStyle:     const TextStyle(color: darkTextSec),
        hintStyle:      const TextStyle(color: darkTextMuted),
      ),
      dividerTheme: const DividerThemeData(color: darkBorder, thickness: 1, space: 1),
      chipTheme: ChipThemeData(
        backgroundColor: darkSurfaceVar,
        labelStyle: const TextStyle(color: darkTextSec, fontSize: 12),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6)),
      ),
      useMaterial3: true,
    );
  }

  /// Backward-compat alias. Old code referencing AppTheme.darkTheme still compiles.
  static ThemeData get darkTheme => dark;
}
