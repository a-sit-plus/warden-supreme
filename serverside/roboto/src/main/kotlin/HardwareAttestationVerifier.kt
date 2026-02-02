package at.asitplus.attestation.android

import at.asitplus.attestation.android.exceptions.AndroidAttestationException

@Deprecated("To be removed in 1.1", replaceWith = ReplaceWith("Roboto"))
object HardwareAttestationVerifier {

    @JvmOverloads
    @Deprecated("To be removed in 1.1", replaceWith = ReplaceWith("Roboto"))
    operator fun invoke(
        attestationConfiguration: AndroidAttestationConfiguration,
        verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean = { expected, actual -> expected contentEquals actual }
    ): Roboto {
        if (attestationConfiguration.disableHardwareAttestation) throw object :
            AndroidAttestationException("Hardware attestation is disabled!", null) {}
        if (attestationConfiguration.hardwareTrustedRoots.isEmpty()) throw object :
            AndroidAttestationException("No hardware attestation trust anchors configured", null) {}
        return Roboto(attestationConfiguration, verifyChallenge)
    }
}