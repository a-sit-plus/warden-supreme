package examples

import ALIAS
import ENDPOINT_CHALLENGE
import at.asitplus.attestation.supreme.AttestationClient
import at.asitplus.attestation.supreme.AttestationResponse
import at.asitplus.attestation.supreme.attestationEndpointUrl
import at.asitplus.attestation.supreme.createAttestationProof
import at.asitplus.attestation.supreme.createCsr
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.supreme.dsl.REQUIRED
import at.asitplus.signum.supreme.os.PlatformSigningProvider
import io.ktor.client.*
import io.ktor.http.*
import kotlin.time.Duration.Companion.seconds

val ktorClient = HttpClient()

object myCertStore {
    fun store(chain: CertificateChain) {}
}

suspend fun main() {


 /*(1)!*/val client = AttestationClient(ktorClient)
 /*(2)!*/val challenge = client.getChallenge(Url(ENDPOINT_CHALLENGE)).getOrThrow()

 /*(3)!*/val signer = PlatformSigningProvider.createSigningKey(ALIAS) {
        ec {
            curve = ECCurve.SECP_256_R_1
            purposes {
                signing = true
                keyAgreement = true
            }
        }
        hardware {
            backing = REQUIRED
            protection {
                factors {
                    biometry = true
                }
                timeout = 30.seconds
            }
        }
    }.getOrThrow() //handle error

 /*(4)!*/val csr = signer.createCsr(challenge).getOrThrow()

 /*(4)!*/when (val result = client.attest(csr, challenge.attestationEndpointUrl)) {
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
}

