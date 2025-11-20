package at.asitplus.warden.demoapp

import android.os.Build
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.supreme.os.PlatformSigningProvider
import at.asitplus.signum.supreme.signature
import kotlinx.serialization.json.Json
import kotlin.time.Clock
import kotlin.time.ExperimentalTime

class AndroidPlatform : Platform {
    override val name: String = "Android ${!isEmulatorByBuildProps()}"
}

actual fun getPlatform(): Platform = AndroidPlatform()


fun isEmulatorByBuildProps(): Boolean {
    val model = Build.MODEL.lowercase()
    val product = Build.PRODUCT.lowercase()
    val device = Build.DEVICE.lowercase()
    val brand = Build.BRAND.lowercase()
    val manufacturer = Build.MANUFACTURER.lowercase()

    return when {
        // Generic Android emulator
        product.contains("sdk") ||
                product.contains("emulator") ||
                product.contains("generic") -> true

        // Common strings in model / device
        model.contains("android sdk built for x86") ||
                model.contains("google_sdk") ||
                model.contains("emulator") ||
                device.contains("generic") -> true

        // Genymotion
        manufacturer.contains("genymotion") -> true

        // Other vendors sometimes use these
        brand.startsWith("generic") && device.startsWith("generic") -> true

        else -> false
    }
}