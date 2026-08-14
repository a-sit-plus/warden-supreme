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




    // --8<-- [start:minimal-client-flow]
 /*(1)!*/val client = AttestationClient(ktorClient)

 /*(2)!*/when (val result = client.performAttestationFlow(ALIAS, Url(ENDPOINT_CHALLENGE)) { requested ->
        requested.map { attribute ->
            when (attribute.name) {
                "accountId" -> /*(3)!*/"account-123"
                "riskScore" -> /*(4)!*/null
                else -> error("Unsupported requested attribute: ${attribute.name}")
            }
        }
    }) {
        is AttestationResponse.Success ->/*(5)!*/myCertStore.store(result.certificateChain) //<-- You're golden!

        is AttestationResponse.Failure -> {
         /*(6)!*/when(result.kind) {
                AttestationResponse.Failure.Type.TRUST -> TODO()
                AttestationResponse.Failure.Type.TIME -> TODO()
                AttestationResponse.Failure.Type.CONTENT -> TODO()
                AttestationResponse.Failure.Type.INTERNAL -> TODO()
            }
        }
    }
    // --8<-- [end:minimal-client-flow]










}
