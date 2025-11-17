package docs.service.callbacks

import at.asitplus.attestation.AttestationResult
import at.asitplus.attestation.supreme.PreAttestationError
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequest
import docs.config.minimal.verifier
import java.util.logging.Level
import java.util.logging.Logger

val csr: Pkcs10CertificationRequest = TODO()
val logger = Logger.getLogger("demo")

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
     /*(5)!*/logger.log(Level.WARNING,"Attestation failed due to $reason. "
            + debugStatement.serializeCompact(), attestationException)
     /*(6)!*/null
    },
 /*(7)!*/onAttestationSuccess = { attestedKey ->
        when (this) {
            is AttestationResult.Android.Verified -> TODO()
            is AttestationResult.IOS.Verified -> TODO()
        }

    }
)/*(8)!*/{ csr ->
    when (this) {
        is AttestationResult.Android.Verified -> TODO()
        is AttestationResult.IOS.Verified -> TODO()
    }
    TODO("Refer to minimum example")
}



}
