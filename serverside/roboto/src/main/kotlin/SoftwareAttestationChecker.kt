package at.asitplus.attestation.android

import at.asitplus.attestation.android.exceptions.AndroidAttestationException
import at.asitplus.attestation.android.exceptions.AttestationValueException
import com.google.android.attestation.ParsedAttestationRecord
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.cache.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.serialization.kotlinx.json.*
import java.security.PublicKey
import java.util.*

class SoftwareAttestationChecker @JvmOverloads constructor(
    attestationConfiguration: AndroidAttestationConfiguration,
    verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean = { expected, actual -> expected contentEquals actual }
) : AndroidAttestationChecker(attestationConfiguration, verifyChallenge) {
    init {
        if (!attestationConfiguration.enableSoftwareAttestation) throw object :
            AndroidAttestationException("Software attestation is disabled!", null) {}
        if (attestationConfiguration.softwareAttestationTrustAnchors.isEmpty()) throw object :
            AndroidAttestationException("No software attestation trust anchors configured", null) {}
    }

    companion object {
        const val GOOGLE_SOFTWARE_EC_ROOT =
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamgu" +
                    "D/9/SQ59dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpA=="
        const val GOOGLE_SOFTWARE_RSA_ROOT =
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCia63rbi5EYe/VDoLmt5TRdSMf" +
                    "d5tjkWP/96r/C3JHTsAsQ+wzfNes7UA+jCigZtX3hwszl94OuE4TQKuvpSe/lWmg" +
                    "MdsGUmX4RFlXYfC78hdLt0GAZMAoDo9Sd47b0ke2RekZyOmLw9vCkT/X11DEHTVm" +
                    "+Vfkl5YLCazOkjWFmwIDAQAB"
    }

    @Throws(AttestationValueException::class)
    override fun ParsedAttestationRecord.verifySecurityLevel() {
        if (attestationSecurityLevel() != ParsedAttestationRecord.SecurityLevel.SOFTWARE) throw AttestationValueException(
            "Attestation security level not software", reason = AttestationValueException.Reason.SEC_LEVEL,
            expectedValue = ParsedAttestationRecord.SecurityLevel.SOFTWARE,
            actualValue = attestationSecurityLevel()
        )
        if (keymasterSecurityLevel() != ParsedAttestationRecord.SecurityLevel.SOFTWARE) throw AttestationValueException(
            "Keymaster security level not software", reason = AttestationValueException.Reason.SEC_LEVEL,
            expectedValue =  ParsedAttestationRecord.SecurityLevel.SOFTWARE,
            actualValue = keymasterSecurityLevel()
        )
    }

    override val trustAnchors: Collection<PublicKey> = attestationConfiguration.softwareAttestationTrustAnchors

    @Throws(AttestationValueException::class)
    override fun ParsedAttestationRecord.verifyAndroidVersion(versionOverride: Int?, osPatchLevel: PatchLevel?, verificationDate: Date) =
        softwareEnforced().verifyAndroidVersion(versionOverride, osPatchLevel, verificationDate)

    @Throws(AttestationValueException::class)
    override fun ParsedAttestationRecord.verifyBootStateAndSystemImage() {
        //impossible
    }

    @Throws(AttestationValueException::class)
    override fun ParsedAttestationRecord.verifyRollbackResistance() = softwareEnforced().verifyRollbackResistance()
}