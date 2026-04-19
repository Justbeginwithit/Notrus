package com.notrus.android.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

enum class NotrusColorTheme(
    val key: String,
    val label: String,
) {
    Ocean(
        key = "ocean",
        label = "Ocean",
    ),
    Graphite(
        key = "graphite",
        label = "Graphite",
    ),
    Forest(
        key = "forest",
        label = "Forest",
    ),
    Sunset(
        key = "sunset",
        label = "Sunset",
    );

    companion object {
        val Default = Ocean

        fun fromKey(raw: String?): NotrusColorTheme {
            if (raw.isNullOrBlank()) {
                return Default
            }
            return entries.firstOrNull { it.key == raw } ?: Default
        }
    }
}

enum class NotrusThemeMode(
    val key: String,
    val label: String,
) {
    System(
        key = "system",
        label = "System",
    ),
    Light(
        key = "light",
        label = "Light",
    ),
    Dark(
        key = "dark",
        label = "Dark",
    );

    companion object {
        val Default = System

        fun fromKey(raw: String?): NotrusThemeMode {
            if (raw.isNullOrBlank()) {
                return Default
            }
            return entries.firstOrNull { it.key == raw } ?: Default
        }
    }
}

@Composable
fun NotrusAndroidTheme(
    themeKey: String = NotrusColorTheme.Default.key,
    themeModeKey: String = NotrusThemeMode.Default.key,
    content: @Composable () -> Unit,
) {
    val preset = NotrusColorTheme.fromKey(themeKey)
    val themeMode = NotrusThemeMode.fromKey(themeModeKey)
    val darkTheme = when (themeMode) {
        NotrusThemeMode.System -> isSystemInDarkTheme()
        NotrusThemeMode.Light -> false
        NotrusThemeMode.Dark -> true
    }
    val scheme = when (preset) {
        NotrusColorTheme.Ocean -> oceanScheme(darkTheme)
        NotrusColorTheme.Graphite -> graphiteScheme(darkTheme)
        NotrusColorTheme.Forest -> forestScheme(darkTheme)
        NotrusColorTheme.Sunset -> sunsetScheme(darkTheme)
    }
    MaterialTheme(
        colorScheme = scheme,
        typography = NotrusTypography,
        content = content,
    )
}

private fun oceanScheme(darkTheme: Boolean) = if (darkTheme) {
    darkColorScheme(
        primary = Ice,
        onPrimary = Night,
        secondary = Color(0xFF8FCEB5),
        tertiary = Color(0xFFFFB37F),
        background = Night,
        onBackground = Color(0xFFF3F7FA),
        surface = Surface,
        onSurface = Color(0xFFF3F7FA),
        surfaceVariant = SurfaceRaised,
        onSurfaceVariant = Color(0xFFE1E9F1),
        outline = Color(0xFF8896A4),
        primaryContainer = Color(0xFF1C3E50),
        onPrimaryContainer = Color(0xFFE8F7FE),
        secondaryContainer = Color(0xFF244136),
        onSecondaryContainer = Color(0xFFE8F6EF),
        errorContainer = Color(0xFF602B22),
        onErrorContainer = Color(0xFFFFDDD6),
    )
} else {
    lightColorScheme(
        primary = Ocean,
        onPrimary = Color.White,
        secondary = Mint,
        tertiary = Ember,
        background = Color(0xFFF6F8FB),
        onBackground = Color(0xFF15202B),
        surface = Color(0xFFFFFFFF),
        onSurface = Color(0xFF15202B),
        surfaceVariant = Color(0xFFE8EDF3),
        onSurfaceVariant = Color(0xFF2D3D4C),
        outline = Color(0xFF6D7A88),
        primaryContainer = Color(0xFFD7EEF9),
        onPrimaryContainer = Color(0xFF0E3341),
        secondaryContainer = Color(0xFFDDF3E6),
        onSecondaryContainer = Color(0xFF183124),
        errorContainer = Color(0xFFFFDCCF),
        onErrorContainer = Color(0xFF3B1207),
    )
}

private fun graphiteScheme(darkTheme: Boolean) = if (darkTheme) {
    darkColorScheme(
        primary = Color(0xFFA7BCFF),
        onPrimary = Color(0xFF112359),
        secondary = Color(0xFF9CD7CC),
        tertiary = Color(0xFFF5C39F),
        background = Color(0xFF0F1117),
        onBackground = Color(0xFFEFF2F8),
        surface = Color(0xFF181B24),
        onSurface = Color(0xFFEFF2F8),
        surfaceVariant = Color(0xFF222836),
        onSurfaceVariant = Color(0xFFE0E5F0),
        outline = Color(0xFF8A92A2),
        primaryContainer = Color(0xFF24346F),
        onPrimaryContainer = Color(0xFFE3E9FF),
        secondaryContainer = Color(0xFF234B45),
        onSecondaryContainer = Color(0xFFE5F5F1),
        errorContainer = Color(0xFF632A32),
        onErrorContainer = Color(0xFFFFDADF),
    )
} else {
    lightColorScheme(
        primary = Color(0xFF3557C8),
        onPrimary = Color.White,
        secondary = Color(0xFF2E786E),
        tertiary = Color(0xFF9A5A2F),
        background = Color(0xFFF7F8FC),
        onBackground = Color(0xFF171C27),
        surface = Color(0xFFFFFFFF),
        onSurface = Color(0xFF171C27),
        surfaceVariant = Color(0xFFE6E9F1),
        onSurfaceVariant = Color(0xFF2F3C4F),
        outline = Color(0xFF687384),
        primaryContainer = Color(0xFFDCE4FF),
        onPrimaryContainer = Color(0xFF172D77),
        secondaryContainer = Color(0xFFD8F1EC),
        onSecondaryContainer = Color(0xFF133933),
        errorContainer = Color(0xFFFFDADF),
        onErrorContainer = Color(0xFF420F1B),
    )
}

private fun forestScheme(darkTheme: Boolean) = if (darkTheme) {
    darkColorScheme(
        primary = Color(0xFFA4DFAF),
        onPrimary = Color(0xFF133624),
        secondary = Color(0xFFB6D79C),
        tertiary = Color(0xFFF0C785),
        background = Color(0xFF0E1511),
        onBackground = Color(0xFFEAF6ED),
        surface = Color(0xFF17221B),
        onSurface = Color(0xFFEAF6ED),
        surfaceVariant = Color(0xFF233126),
        onSurfaceVariant = Color(0xFFDCECDC),
        outline = Color(0xFF819787),
        primaryContainer = Color(0xFF2B5337),
        onPrimaryContainer = Color(0xFFE5F7E9),
        secondaryContainer = Color(0xFF3A4E2E),
        onSecondaryContainer = Color(0xFFF0F8E7),
        errorContainer = Color(0xFF5F2D22),
        onErrorContainer = Color(0xFFFFDED6),
    )
} else {
    lightColorScheme(
        primary = Color(0xFF2F7E4E),
        onPrimary = Color.White,
        secondary = Color(0xFF4D6B32),
        tertiary = Color(0xFF96691F),
        background = Color(0xFFF5FAF5),
        onBackground = Color(0xFF152218),
        surface = Color(0xFFFFFFFF),
        onSurface = Color(0xFF152218),
        surfaceVariant = Color(0xFFE3EEE4),
        onSurfaceVariant = Color(0xFF2C4332),
        outline = Color(0xFF62786A),
        primaryContainer = Color(0xFFD8F2DE),
        onPrimaryContainer = Color(0xFF113A23),
        secondaryContainer = Color(0xFFE2EED2),
        onSecondaryContainer = Color(0xFF223413),
        errorContainer = Color(0xFFFFDDD2),
        onErrorContainer = Color(0xFF421307),
    )
}

private fun sunsetScheme(darkTheme: Boolean) = if (darkTheme) {
    darkColorScheme(
        primary = Color(0xFFFFB18E),
        onPrimary = Color(0xFF51200C),
        secondary = Color(0xFFFFC88A),
        tertiary = Color(0xFFFF93B4),
        background = Color(0xFF1A1010),
        onBackground = Color(0xFFFFF1EE),
        surface = Color(0xFF261718),
        onSurface = Color(0xFFFFF1EE),
        surfaceVariant = Color(0xFF382527),
        onSurfaceVariant = Color(0xFFFFE2DE),
        outline = Color(0xFFB0928F),
        primaryContainer = Color(0xFF6C3018),
        onPrimaryContainer = Color(0xFFFFE5DA),
        secondaryContainer = Color(0xFF62481E),
        onSecondaryContainer = Color(0xFFFFEDCE),
        errorContainer = Color(0xFF6A2636),
        onErrorContainer = Color(0xFFFFD9E0),
    )
} else {
    lightColorScheme(
        primary = Color(0xFFC3502A),
        onPrimary = Color.White,
        secondary = Color(0xFF9A670F),
        tertiary = Color(0xFFA83D62),
        background = Color(0xFFFFF7F4),
        onBackground = Color(0xFF2C1814),
        surface = Color(0xFFFFFFFF),
        onSurface = Color(0xFF2C1814),
        surfaceVariant = Color(0xFFF8E8E3),
        onSurfaceVariant = Color(0xFF533A35),
        outline = Color(0xFF91726E),
        primaryContainer = Color(0xFFFFDCCF),
        onPrimaryContainer = Color(0xFF57230E),
        secondaryContainer = Color(0xFFFBE6C8),
        onSecondaryContainer = Color(0xFF4A2F06),
        errorContainer = Color(0xFFFFDBE3),
        onErrorContainer = Color(0xFF430E1D),
    )
}
