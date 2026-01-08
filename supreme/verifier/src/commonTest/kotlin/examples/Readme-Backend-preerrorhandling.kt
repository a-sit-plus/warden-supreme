package docs.service.callbacks

import at.asitplus.attestation.supreme.PreAttestationError
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequest
import docs.config.minimal.verifier
import java.util.logging.Logger

private val csr: Pkcs10CertificationRequest = TODO()
private val logger = Logger.getLogger("demo")

//@formatter:off
private suspend fun foo() {



val result = verifier.verifyAttestation(
    csr = csr,
    onPreAttestationError = {
        when(this) {
         /*(1)!*/is PreAttestationError.AttestationStatementExtraction  -> TODO()
         /*(2)!*/is PreAttestationError.ChallengeExtraction             -> TODO()
         /*(3)!*/is PreAttestationError.ChallengeVerification           -> TODO()
         /*(3)!*/is PreAttestationError.OperationalError                -> TODO()
        }
    }
) { TODO("Refer to minimum example for certificate issuance") }
















}
