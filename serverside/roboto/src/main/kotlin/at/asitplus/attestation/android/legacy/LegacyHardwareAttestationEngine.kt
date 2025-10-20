package at.asitplus.attestation.android.at.asitplus.attestation.android.legacy

import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.PatchLevel
import at.asitplus.attestation.android.exceptions.AndroidAttestationException
import at.asitplus.attestation.android.exceptions.AttestationValueException
import com.google.android.attestation.ParsedAttestationRecord
import java.util.*

class LegacyHardwareAttestationEngine @JvmOverloads constructor(
    attestationConfiguration: AndroidAttestationConfiguration,
    verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean = { expected, actual -> expected contentEquals actual }
) : LegacyAttestationEngine(attestationConfiguration, verifyChallenge) {

    init {
        if (attestationConfiguration.disableHardwareAttestation) throw object :
            AndroidAttestationException("Hardware attestation is disabled!", null) {}
        if (attestationConfiguration.hardwareAttestationTrustAnchors.isEmpty()) throw object :
            AndroidAttestationException("No hardware attestation trust anchors configured", null) {}
    }

    @Throws(AttestationValueException::class)
    override fun ParsedAttestationRecord.verifySecurityLevel() {
        if (attestationConfiguration.requireStrongBox) {
            if (attestationSecurityLevel() != ParsedAttestationRecord.SecurityLevel.STRONG_BOX)
                throw AttestationValueException(
                    "Attestation security level not StrongBox",
                    reason = AttestationValueException.Reason.SEC_LEVEL,
                    expectedValue = ParsedAttestationRecord.SecurityLevel.STRONG_BOX,
                    actualValue = attestationSecurityLevel()
                )
            if (keymasterSecurityLevel() != ParsedAttestationRecord.SecurityLevel.STRONG_BOX)
                throw AttestationValueException(
                    "Keymaster security level not StrongBox",
                    reason = AttestationValueException.Reason.SEC_LEVEL,
                    expectedValue = ParsedAttestationRecord.SecurityLevel.STRONG_BOX,
                    actualValue = keymasterSecurityLevel()
                )
        } else {
            if (attestationSecurityLevel() == ParsedAttestationRecord.SecurityLevel.SOFTWARE)
                throw AttestationValueException(
                    "Attestation security level software",
                    reason = AttestationValueException.Reason.SEC_LEVEL,
                    expectedValue = ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT,
                    actualValue = attestationSecurityLevel()
                )
            if (keymasterSecurityLevel() == ParsedAttestationRecord.SecurityLevel.SOFTWARE)
                throw AttestationValueException(
                    "Keymaster security level software",
                    reason = AttestationValueException.Reason.SEC_LEVEL,
                    expectedValue = ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT,
                    actualValue = keymasterSecurityLevel()
                )
        }
    }

    override val trustAnchors = attestationConfiguration.hardwareAttestationTrustAnchors

    @Throws(AttestationValueException::class)
    override fun ParsedAttestationRecord.verifyAndroidVersion(versionOverride: Int?, osPatchLevel: PatchLevel?, verificationDate: Date) =
        teeEnforced().verifyAndroidVersion(versionOverride, osPatchLevel, verificationDate)

    @Throws(AttestationValueException::class)
    override fun ParsedAttestationRecord.verifyBootStateAndSystemImage() = teeEnforced().verifySystemLocked()

    @Throws(AttestationValueException::class)
    override fun ParsedAttestationRecord.verifyRollbackResistance() = teeEnforced().verifyRollbackResistance()
}