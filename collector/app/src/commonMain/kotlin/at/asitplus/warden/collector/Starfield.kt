package at.asitplus.warden.collector

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.withFrameNanos
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import kotlin.random.Random

private const val STAR_COUNT = 260

private class Star(var x: Float, var y: Float, var z: Float) {
    var pz: Float = z
    fun respawn(rnd: Random) {
        x = rnd.nextFloat() * 2f - 1f
        y = rnd.nextFloat() * 2f - 1f
        z = 1f
        pz = 1f
    }
}

/**
 * A perspective starfield.
 *
 * Idle it is static (no animation, no redraws). While [warp] is true the stars accelerate toward the
 * viewer and render as streaks — a Star-Trek-style warp jump — then decelerate back to a static field
 * when [warp] returns to false.
 */
@Composable
fun StarfieldBackground(
    warp: Boolean,
    modifier: Modifier = Modifier,
    starColor: Color = Color(0xFFDFF6FF),
    streakColor: Color = Color(0xFF9CE9FF),
) {
    val stars = remember {
        val rnd = Random(42)
        List(STAR_COUNT) { Star(rnd.nextFloat() * 2f - 1f, rnd.nextFloat() * 2f - 1f, rnd.nextFloat() * 0.9f + 0.1f) }
    }
    val speed = remember { Animatable(0f) }
    var tick by remember { mutableIntStateOf(0) }

    // Ramp warp speed up/down whenever [warp] flips.
    LaunchedEffect(warp) {
        speed.animateTo(
            targetValue = if (warp) 1f else 0f,
            animationSpec = tween(durationMillis = if (warp) 650 else 1200, easing = FastOutSlowInEasing),
        )
    }

    // Frame loop runs only while there is motion (warp active or still decelerating); otherwise the
    // field is static and nothing redraws.
    val animating = warp || speed.value > 0.001f
    LaunchedEffect(animating) {
        if (!animating) return@LaunchedEffect
        val rnd = Random(7)
        var last = 0L
        while (true) {
            withFrameNanos { now ->
                val dt = if (last == 0L) 0f else ((now - last) / 1_000_000_000f).coerceAtMost(0.05f)
                last = now
                val sp = speed.value
                stars.forEach { star ->
                    star.pz = star.z
                    star.z -= sp * dt * 1.1f
                    if (star.z <= 0.02f) star.respawn(rnd)
                }
                tick++
            }
        }
    }

    Canvas(modifier) {
        tick                 // read to invalidate the draw each animated frame
        val sp = speed.value // read to invalidate on speed changes (incl. the final settle to 0)
        val cx = size.width / 2f
        val cy = size.height / 2f
        val scale = size.minDimension * 0.75f

        stars.forEach { star ->
            val sx = cx + (star.x / star.z) * scale
            val sy = cy + (star.y / star.z) * scale
            if (sx < 0f || sx > size.width || sy < 0f || sy > size.height) return@forEach
            val brightness = (1f - star.z).coerceIn(0f, 1f)
            if (sp > 0.06f) {
                val px = cx + (star.x / star.pz) * scale
                val py = cy + (star.y / star.pz) * scale
                drawLine(
                    // Brighter trails during warp (alpha ramps toward full as speed/brightness rise).
                    color = streakColor.copy(alpha = ((0.55f + 0.45f * brightness) * (0.65f + 0.35f * sp)).coerceAtMost(1f)),
                    start = Offset(px, py),
                    end = Offset(sx, sy),
                    strokeWidth = 2f + 3f * brightness,
                )
            } else {
                drawCircle(
                    color = starColor.copy(alpha = 0.2f + 0.7f * brightness),
                    // Twice the diameter of the previous static field.
                    radius = 1.2f + 3.4f * brightness,
                    center = Offset(sx, sy),
                )
            }
        }
    }
}
