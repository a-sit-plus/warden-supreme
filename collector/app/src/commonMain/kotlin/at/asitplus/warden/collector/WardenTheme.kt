package at.asitplus.warden.collector

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

/** Brand palette, mirroring docs/docs/stylesheets (GitHub-dark base + cyan accent). */
internal object WardenPalette {
    val Background = Color(0xFF070B10)     // near-black, slightly darker than the docs #0D1117 for the starfield
    val Surface = Color(0xFF0D1117)
    val SurfaceVariant = Color(0xFF1E242A)
    val OnBackground = Color(0xFFF0F6FC)
    val OnSurfaceVariant = Color(0xFF9FB2C2)
    val Cyan = Color(0xFF00BEFF)           // --md-accent-fg-color
    val LogoCyan = Color(0xFF005b79)       // the logo's own cyan
    val Green = Color(0xFF2FB170)          // code-hl string
    val Red = Color(0xFFE6695B)            // code-hl number / errors
    val Outline = Color(0xFF243441)
}

private val WardenColors = darkColorScheme(
    // Match the logo's teal so the Attest button (and other primary accents) align with the wordmark.
    primary = WardenPalette.LogoCyan,
    onPrimary = Color(0xFFFFFFFF), // white, legible on the dark-teal button

    secondary = WardenPalette.Red,
    onSecondary = Color(0xFF2A0A06),
    tertiary = WardenPalette.Green,
    onTertiary = Color(0xFF04241A),
    background = WardenPalette.Background,
    onBackground = WardenPalette.OnBackground,
    surface = WardenPalette.Surface,
    onSurface = WardenPalette.OnBackground,
    surfaceVariant = WardenPalette.SurfaceVariant,
    onSurfaceVariant = WardenPalette.OnSurfaceVariant,
    error = WardenPalette.Red,
    outline = WardenPalette.Outline,
)

/** App theme. Always dark — deliberately not switchable to light, matching the docs site. */
@Composable
fun WardenTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = WardenColors, content = content)
}
