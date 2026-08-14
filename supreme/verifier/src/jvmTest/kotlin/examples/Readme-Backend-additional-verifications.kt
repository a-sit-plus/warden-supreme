package examples.docs.service.additionalverifications

import at.asitplus.attestation.supreme.AttestationResponse
import at.asitplus.attestation.supreme.AttestationProof
import at.asitplus.attestation.supreme.attestedAttributes
import at.asitplus.signum.indispensable.pki.CertificateChain
import examples.docs.config.minimal.verifier

private val proof: AttestationProof = TODO()
private val expectedAccountId = "account-123"

private suspend fun issueCertificateChain(proof: AttestationProof): CertificateChain = TODO()

private suspend fun foo() {



// --8<-- [start:additional-verifications]
val response = verifier.verifyAttestation(
 /*(1)!*/attestationProof = proof,
 /*(2)!*/additionalVerifications = { receivedProof, _ ->
        val accountId = /*(3)!*/receivedProof.attestedAttributes["accountId"] as? String
        if (accountId != expectedAccountId) {
         /*(4)!*/AttestationResponse.Failure(
                AttestationResponse.Failure.Type.CONTENT,
                "Attested account does not match account policy"
            )
        } else {
         /*(5)!*/null
        }
    },
 /*(6)!*/certificateIssuer = { verifiedProof ->
        issueCertificateChain(verifiedProof)
    }
// --8<-- [end:additional-verifications]
)



}
