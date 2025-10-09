package at.asitplus.attestation.android.at.asitplus.attestation.android.legacy

import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.PatchLevel
import at.asitplus.attestation.android.exceptions.AndroidAttestationException
import at.asitplus.attestation.android.exceptions.AttestationValueException
import com.google.android.attestation.ParsedAttestationRecord
import java.time.Instant
import java.util.*

class LegacyNougatHybridAttestationEngine @JvmOverloads constructor(
    attestationConfiguration: AndroidAttestationConfiguration,
    verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean = { expected, actual -> expected contentEquals actual }
) : LegacyAttestationEngine(attestationConfiguration, verifyChallenge) {

    init {
        if (!attestationConfiguration.enableNougatAttestation) throw object :
            AndroidAttestationException("Nougat attestation is disabled!", null) {}
        if (attestationConfiguration.hardwareAttestationTrustAnchors.isEmpty()) throw object :
            AndroidAttestationException("No Nougat (Software) attestation trust anchors configured", null) {}
    }

    @Throws(AttestationValueException::class)
    override fun ParsedAttestationRecord.verifySecurityLevel() {
        if (attestationConfiguration.requireStrongBox) {
            if (keymasterSecurityLevel() != ParsedAttestationRecord.SecurityLevel.STRONG_BOX) throw AttestationValueException(
                "Keymaster security level not StrongBox", reason = AttestationValueException.Reason.SEC_LEVEL,
                expectedValue = ParsedAttestationRecord.SecurityLevel.STRONG_BOX,
                actualValue = keymasterSecurityLevel()
            )
        } else {
            if (keymasterSecurityLevel() == ParsedAttestationRecord.SecurityLevel.SOFTWARE) throw AttestationValueException(
                "Keymaster security level software", reason = AttestationValueException.Reason.SEC_LEVEL,
                expectedValue = ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT,
                actualValue = keymasterSecurityLevel()
            )
        }
        if (attestationSecurityLevel() != ParsedAttestationRecord.SecurityLevel.SOFTWARE) {
            throw AttestationValueException(
                "Attestation security level not software", reason = AttestationValueException.Reason.SEC_LEVEL,
                expectedValue = ParsedAttestationRecord.SecurityLevel.SOFTWARE,
                actualValue = attestationSecurityLevel()
            )
        }
    }

    override val trustAnchors = attestationConfiguration.softwareAttestationTrustAnchors

    @Throws(AttestationValueException::class)
    override fun ParsedAttestationRecord.verifyAndroidVersion(versionOverride: Int?, osPatchLevel: PatchLevel?, verificationDate: Date) {
        //impossible
    }

    @Throws(AttestationValueException::class)
    override fun ParsedAttestationRecord.verifyBootStateAndSystemImage() {
        //impossible
    }

    @Throws(AttestationValueException::class)
    override fun ParsedAttestationRecord.verifyRollbackResistance() = teeEnforced().verifyRollbackResistance()

    override fun ParsedAttestationRecord.verifyAttestationTime(verificationDate: Instant) {
        //impossible
    }
}