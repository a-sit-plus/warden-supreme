package examples.min

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

 /*(2)!*/when (val result = client.performAttestationFlow(ALIAS, Url(ENDPOINT_CHALLENGE))) {
        is AttestationResponse.Success ->/*(3)!*/myCertStore.store(result.certificateChain) //<-- You're golden!

        is AttestationResponse.Failure -> {
         /*(4)!*/when(result.kind) {
                AttestationResponse.Failure.Type.TRUST -> TODO()
                AttestationResponse.Failure.Type.TIME -> TODO()
                AttestationResponse.Failure.Type.CONTENT -> TODO()
                AttestationResponse.Failure.Type.INTERNAL -> TODO()
            }
        }
    }










}

