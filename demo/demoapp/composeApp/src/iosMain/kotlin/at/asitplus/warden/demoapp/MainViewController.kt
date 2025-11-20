package at.asitplus.warden.demoapp

import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.window.ComposeUIViewController
import com.russhwolf.settings.NSUserDefaultsSettings
import platform.Foundation.NSUserDefaults

fun MainViewController() = ComposeUIViewController {
    val focusManager = LocalFocusManager.current
    Box(
        modifier = Modifier.fillMaxSize()
            .then(Modifier.safeDrawingPadding())
            .pointerInput(Unit) {
                detectTapGestures(onTap = {
                    focusManager.clearFocus()
                })
            }
    ) {
        App(NSUserDefaultsSettings(NSUserDefaults()))
    }
}
