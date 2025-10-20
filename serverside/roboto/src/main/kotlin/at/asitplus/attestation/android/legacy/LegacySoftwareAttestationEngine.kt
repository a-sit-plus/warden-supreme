package at.asitplus.attestation.android.at.asitplus.attestation.android.legacy

import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.PatchLevel
import at.asitplus.attestation.android.exceptions.AndroidAttestationException
import at.asitplus.attestation.android.exceptions.AttestationValueException
import com.google.android.attestation.ParsedAttestationRecord
import java.security.PublicKey
import java.util.*

class LegacySoftwareAttestationEngine @JvmOverloads constructor(
    attestationConfiguration: AndroidAttestationConfiguration,
    verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean = { expected, actual -> expected contentEquals actual }
) : LegacyAttestationEngine(attestationConfiguration, verifyChallenge) {
    init {
        if (!attestationConfiguration.enableSoftwareAttestation) throw object :
            AndroidAttestationException("Software attestation is disabled!", null) {}
        if (attestationConfiguration.softwareAttestationTrustAnchors.isEmpty()) throw object :
            AndroidAttestationException("No software attestation trust anchors configured", null) {}
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