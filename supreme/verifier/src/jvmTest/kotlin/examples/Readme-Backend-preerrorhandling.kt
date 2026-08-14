package examples.docs.service.callbacks

import at.asitplus.attestation.supreme.PreAttestationError
import at.asitplus.attestation.supreme.AttestationProof
import examples.docs.config.minimal.verifier
import java.util.logging.Logger

private val proof: AttestationProof = TODO()
private val logger = Logger.getLogger("demo")

//@formatter:off
private suspend fun foo() {



// --8<-- [start:pre-attestation-error-handling]
val result = verifier.verifyAttestation(
    attestationProof = proof,
    onPreAttestationError = {
        when(this) {
         /*(1)!*/is PreAttestationError.AttestationStatementExtraction  -> TODO()
                  is PreAttestationError.AugmentedAttestationStatementExtraction -> TODO()
         /*(2)!*/is PreAttestationError.ChallengeExtraction             -> TODO()
         /*(3)!*/is PreAttestationError.ChallengeVerification           -> TODO()
         /*(4)!*/is PreAttestationError.ClientDataValidation           -> when (reason) {
                      PreAttestationError.ClientDataValidation.Reason.AUTHENTICATION_METHOD_MISMATCH -> TODO()
                      PreAttestationError.ClientDataValidation.Reason.DUPLICATE_CSR_ATTRIBUTE_OID -> TODO()
                      PreAttestationError.ClientDataValidation.Reason.MALFORMED_CSR_EXTENSION_REQUEST -> TODO()
                      PreAttestationError.ClientDataValidation.Reason.DUPLICATE_CSR_EXTENSION_OID -> TODO()
                      PreAttestationError.ClientDataValidation.Reason.NON_CANONICAL_CSR_ATTRIBUTE_ORDER -> TODO()
                      PreAttestationError.ClientDataValidation.Reason.ATTESTATION_BINDING -> TODO()
                      PreAttestationError.ClientDataValidation.Reason.ATTESTED_PUBLIC_KEY_MISMATCH -> TODO()
                      PreAttestationError.ClientDataValidation.Reason.REQUESTED_ATTRIBUTES_EXTRACTION -> TODO()
                      PreAttestationError.ClientDataValidation.Reason.REQUESTED_ATTRIBUTES_MISMATCH -> TODO()
                  }
         /*(3)!*/is PreAttestationError.OperationalError                -> TODO()
        }
    }
) { TODO("Refer to minimum example for certificate issuance") }
// --8<-- [end:pre-attestation-error-handling]
















}
