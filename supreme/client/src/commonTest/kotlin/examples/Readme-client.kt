package examples

import ALIAS
import ENDPOINT_CHALLENGE
import at.asitplus.attestation.supreme.*
import at.asitplus.signum.indispensable.pki.CertificateChain
import io.ktor.client.*
import io.ktor.http.*

val ktorClient = HttpClient()
object myCertStore {
    fun store(chain: CertificateChain) {}
}
suspend fun main() {




 /*(1)!*/val client = AttestationClient(ktorClient)
 /*(2)!*/val challenge = client.getChallenge(Url(ENDPOINT_CHALLENGE)).getOrThrow()

 /*(3)!*/val csr = challenge.createAttestationProof(ALIAS).getOrThrow()
 /*(4)!*/when (val result = client.attest(csr, challenge.attestationEndpointUrl)) {
        is AttestationResponse.Success -> {
        /*(5)!*/myCertStore.store(result.certificateChain) //<-- You're golden!
        }
        is AttestationResponse.Failure -> {
         /*(6)!*/when(result.kind) {
                AttestationResponse.Failure.Type.TRUST -> TODO()
                AttestationResponse.Failure.Type.TIME -> TODO()
                AttestationResponse.Failure.Type.CONTENT -> TODO()
                AttestationResponse.Failure.Type.INTERNAL -> TODO()
            }
        }
    }
}

