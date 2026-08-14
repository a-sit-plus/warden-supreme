package examples

import ALIAS
import ENDPOINT_CHALLENGE
import at.asitplus.attestation.supreme.AttestationClient
import at.asitplus.attestation.supreme.AttestationResponse
import at.asitplus.attestation.supreme.attestationEndpointUrl
import at.asitplus.attestation.supreme.createAttestationProof
import io.ktor.http.*


suspend fun stepbystep() {


    // --8<-- [start:step-by-step-client-flow]
 /*(1)!*/val client = AttestationClient(ktorClient)
 /*(2)!*/val challenge = client.getChallenge(Url(ENDPOINT_CHALLENGE)).getOrThrow()

 /*(3)!*/val proof = challenge.createAttestationProof(ALIAS,
     authPromptMessage = "Authenticate for proof of possession",
     authPromptCancelText = "Abort",
     /*additional extensions and attributes go here*/
     ) { requested ->
        requested.map { attribute ->
            when (attribute.name) {
                "accountId" -> "account-123"
                "riskScore" -> null
                else -> error("Unsupported requested attribute: ${attribute.name}")
            }
        }
    }.getOrThrow() //handle error

 /*(4)!*/when (val result = client.attest(proof, challenge.attestationEndpointUrl)) {
        is AttestationResponse.Success -> {
         /*(5)!*/myCertStore.store(result.certificateChain) //<-- You're golden!
        }

        is AttestationResponse.Failure -> {
         /*(6)!*/when (result.kind) {
                AttestationResponse.Failure.Type.TRUST -> TODO()
                AttestationResponse.Failure.Type.TIME -> TODO()
                AttestationResponse.Failure.Type.CONTENT -> TODO()
                AttestationResponse.Failure.Type.INTERNAL -> TODO()
            }
        }
    }
    // --8<-- [end:step-by-step-client-flow]



}
