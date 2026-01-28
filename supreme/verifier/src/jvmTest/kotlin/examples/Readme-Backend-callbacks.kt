package examples.docs.service.callbacks

import at.asitplus.attestation.AttestationResult
import at.asitplus.attestation.supreme.PreAttestationError
import at.asitplus.attestation.supreme.nonce
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequest
import examples.docs.config.minimal.verifier
import java.util.logging.Level
import java.util.logging.Logger

private val csr: Pkcs10CertificationRequest = TODO()
private val logger = Logger.getLogger("demo")

private suspend fun foo() {




val result = verifier.verifyAttestation(
 /*(1)!*/csr = csr,
 /*(2)!*/onChallengeValidated = { csr ->
        val customPayload = additionalPayload
        logger.log(Level.FINE,
            "Challenge validated (payload=$customPayload) based on nonce ${csr.tbsCsr.nonce} from CSR")
    },
 /*(3)!*/onPreAttestationError = {
        when (this) {
            is PreAttestationError.AttestationStatementExtraction -> TODO()
            is PreAttestationError.ChallengeExtraction -> TODO()
            is PreAttestationError.ChallengeVerification -> TODO()
            is PreAttestationError.OperationalError -> TODO()
        }
     /*(4)!*/null
    },
 /*(5)!*/onAttestationError = { debugStatement ->
        val attestationException = cause
        val reason = explanation
     /*(6)!*/logger.log(Level.WARNING,"Attestation failed due to $reason. "
            + debugStatement.serializeCompact(), attestationException)
     /*(7)!*/null
    },
 /*(8)!*/onAttestationSuccess = { attestedKey ->
        when (this) {
            is AttestationResult.Android.Verified -> TODO()
            is AttestationResult.IOS.Verified -> TODO()
        }

    }
)/*(9)!*/{ csr ->
    when (this) {
        is AttestationResult.Android.Verified -> TODO()
        is AttestationResult.IOS.Verified -> TODO()
    }
    TODO("Refer to minimum example for certificate issuance")
}



}
