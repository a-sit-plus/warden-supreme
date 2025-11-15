package at.asitplus.attestation.supreme

import android.os.Build
import at.asitplus.catchingUnwrapped

internal actual fun getDeviceName(): String = catchingUnwrapped {
    val manufacturer = Build.MANUFACTURER
    val model = Build.MODEL

    val make = if (model.startsWith(manufacturer, ignoreCase = true)) {
        model
    } else {
        "$manufacturer $model"
    }
 "$make (${Build.DEVICE})"
}.getOrElse { "Android Device" }