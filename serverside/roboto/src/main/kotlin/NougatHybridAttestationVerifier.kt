package at.asitplus.attestation.android

import at.asitplus.attestation.android.exceptions.AndroidAttestationException
import at.asitplus.attestation.android.exceptions.AttestationValueException
import com.google.android.attestation.ParsedAttestationRecord
import java.time.Instant
import java.util.*

@Deprecated("To be removed in 1.0.0", replaceWith = ReplaceWith("NougatHybridAttestationVerifier"))
typealias NougatHybridAttestationChecker = NougatHybridAttestationVerifier
class NougatHybridAttestationVerifier @JvmOverloads constructor(
    attestationConfiguration: AndroidAttestationConfiguration,
    verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean = { expected, actual -> expected contentEquals actual }
) : Roboto(attestationConfiguration, verifyChallenge) {

    init {
        if (!attestationConfiguration.enableNougatAttestation) throw object :
            AndroidAttestationException("Nougat attestation is disabled!", null) {}
        if (attestationConfiguration.hardwareTrustedRoots.isEmpty()) throw object :
            AndroidAttestationException("No Nougat (Software) attestation trust anchors configured", null) {}
    }

    @Throws(AttestationValueException::class)
    override fun ParsedAttestationRecord.verifySecurityLevel(override: Boolean?/*ignored*/) {
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

    override val trustAnchors = attestationConfiguration.softwareTrustedRoots

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