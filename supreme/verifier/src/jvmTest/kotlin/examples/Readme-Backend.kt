package examples.docs.service

import at.asitplus.attestation.supreme.decodeAttestationProof
import at.asitplus.attestation.supreme.tbsCsr
import at.asitplus.signum.Signum

import at.asitplus.signum.indispensable.pki.*
import at.asitplus.signum.indispensable.sign.sign
import at.asitplus.signum.supreme.installSupreme
import at.asitplus.signum.dsl.ec
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.signum.indispensable.sign.Signer
import examples.docs.config.minimal.verifier
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days

val PATH_CHALLENGE = "/api/v1/challenge"
val PATH_ATTEST = "/api/v1/attest"

val publicEndpoint: String = ""
val signer = kotlinx.coroutines.runBlocking {
    at.asitplus.signum.Signum.installSupreme()
    Signer.Ephemeral { ec { } }
}

var issuerName = X500Name(listOf(
    RelativeDistinguishedName(
        at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue.CommonName("Supreme Verifier")
    )
))
var subjectName = X500Name(listOf(
    RelativeDistinguishedName(
        at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue.CommonName("Supreme Client")
    )
))

val caCert: Certificate = TODO()













// --8<-- [start:backend-server]
val server = embeddedServer(Netty, port = 8080) {
    /*(1)!*/install(ContentNegotiation) { json() }

    routing {
     /*(2)!*/get(PATH_CHALLENGE) {
           call.respond(
              /*(3)!*/verifier.issueChallenge(/*(4)!*/"$publicEndpoint/$PATH_ATTEST")
            )
        }
     /*(5)!*/post(PATH_ATTEST) {
         /*(6)!*/val proof = verifier.decodeAttestationProof(call.receive<ByteArray>()).getOrThrow()
            val result = verifier.verifyAttestation(proof) { received ->
                val tbsCsr = received.tbsCsr
             /*(7)!*/val leafCertificate = signer.sign(
                 /*(8)!*/TbsCertificate(
                      /*(9)!*/serialNumber = Asn1Integer.fromUnsignedByteArray(byteArrayOf(1) + Random.nextBytes(19)),
                      /*(10)!*/publicKey = tbsCsr.publicKey,
                         signatureAlgorithm = signer.signatureAlgorithm,
                         validFrom = Clock.System.now(),
                         validUntil = Clock.System.now() + 10.days,
                         issuerName = issuerName,
                         subjectName = subjectName,
                    )
                )
             /*(11)!*/listOf(leafCertificate, caCert)
            }
         /*(12)!*/call.respond(result)
        }
    }
}.start(wait = false)
// --8<-- [end:backend-server]
