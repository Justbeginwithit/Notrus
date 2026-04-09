package com.notrus.android.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val DarkScheme = darkColorScheme(
    primary = Ice,
    onPrimary = Night,
    secondary = Mint,
    tertiary = Ember,
    background = Night,
    onBackground = Fog,
    surface = Surface,
    onSurface = Fog,
    surfaceVariant = SurfaceRaised,
    outline = Stroke,
)

private val LightScheme = lightColorScheme(
    primary = Ocean,
    onPrimary = Fog,
    secondary = Mint,
    tertiary = Ember,
    background = Fog,
    onBackground = Night,
    surface = Color(0xFFF7FBFD),
    onSurface = Night,
    surfaceVariant = Color(0xFFDCEAF0),
    outline = Color(0x2208151D),
)

@Composable
fun NotrusAndroidTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (isSystemInDarkTheme()) DarkScheme else LightScheme,
        typography = NotrusTypography,
        content = content,
    )
}
