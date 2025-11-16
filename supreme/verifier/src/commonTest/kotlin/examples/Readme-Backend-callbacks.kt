package docs.service.callbacks

import at.asitplus.attestation.AttestationResult
import at.asitplus.attestation.supreme.PreAttestationError
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequest
import docs.config.minimal.verifier

val csr: Pkcs10CertificationRequest = TODO()


suspend fun foo() {




val result = verifier.verifyAttestation(
 /*(1)!*/csr = csr,
 /*(2)!*/onPreAttestationError = {
        when (this) {
            is PreAttestationError.AttestationStatementExtraction -> TODO()
            is PreAttestationError.ChallengeExtraction -> TODO()
            is PreAttestationError.ChallengeVerification -> TODO()
            is PreAttestationError.OperationalError -> TODO()
        }
     /*(3)!*/null
    },
 /*(4)!*/onAttestationError = { debugStatement ->
        val attestationException = cause
        val reason = explanation
     /*(4)!*/null
    },
 /*(5)!*/onAttestationSuccess = { attestedKey ->
        when (this) {
            is AttestationResult.Android.Verified -> TODO()
            is AttestationResult.IOS.Verified -> TODO()
        }

    }
)/*(6)!*/{ csr ->
    when (this) {
        is AttestationResult.Android.Verified -> TODO()
        is AttestationResult.IOS.Verified -> TODO()
    }
    TODO("Certificate issuing logic")
}
}
