package at.asitplus.attestation.android

import at.asitplus.attestation.android.exceptions.AndroidAttestationException

@Deprecated("To be removed in 1.1", replaceWith = ReplaceWith("Roboto"))
object SoftwareAttestationVerifier {
    @Deprecated("To be removed in 1.1")
    const val GOOGLE_SOFTWARE_EC_ROOT =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamgu" +
                "D/9/SQ59dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpA=="

    @Deprecated("To be removed in 1.1")
    const val GOOGLE_SOFTWARE_RSA_ROOT =
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCia63rbi5EYe/VDoLmt5TRdSMf" +
                "d5tjkWP/96r/C3JHTsAsQ+wzfNes7UA+jCigZtX3hwszl94OuE4TQKuvpSe/lWmg" +
                "MdsGUmX4RFlXYfC78hdLt0GAZMAoDo9Sd47b0ke2RekZyOmLw9vCkT/X11DEHTVm" +
                "+Vfkl5YLCazOkjWFmwIDAQAB"

    @JvmOverloads
    @Deprecated("To be removed in 1.1", replaceWith = ReplaceWith("Roboto"))
    operator fun invoke(
        attestationConfiguration: AndroidAttestationConfiguration,
        verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean = { expected, actual -> expected contentEquals actual }
    ): Roboto {
        if (!attestationConfiguration.enableSoftwareAttestation) throw object :
            AndroidAttestationException("Software attestation is disabled!", null) {}
        if (attestationConfiguration.softwareTrustedRoots.isEmpty()) throw object :
            AndroidAttestationException("No software attestation trust anchors configured", null) {}

        return Roboto(attestationConfiguration, verifyChallenge)
    }
}

