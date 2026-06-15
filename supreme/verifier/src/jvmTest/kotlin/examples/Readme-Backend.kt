package examples.docs.service

import at.asitplus.awesn1.nextPositiveAsn1Integer
import at.asitplus.signum.indispensable.decodeFromDer
import at.asitplus.signum.indispensable.pki.*
import at.asitplus.signum.supreme.sign
import at.asitplus.signum.supreme.sign.Signer
import examples.docs.config.minimal.verifier
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.kotlincrypto.random.CryptoRand
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days

val PATH_CHALLENGE = "/api/v1/challenge"
val PATH_ATTEST = "/api/v1/attest"

val publicEndpoint: String = ""
val signer = Signer.Ephemeral {
    ec { }
}.getOrThrow()

var issuerName = listOf(
    RelativeDistinguishedName(
        AttributeTypeAndValue.CommonName("Supreme Verifier")
    )
)
var subjectName = listOf(
    RelativeDistinguishedName(
        AttributeTypeAndValue.CommonName("Supreme Client")
    )
)

val caCert: Certificate = TODO()






val server = embeddedServer(Netty, port = 8080) {
    /*(1)!*/install(ContentNegotiation) { json() }

    routing {
        /*(2)!*/get(PATH_CHALLENGE) {
        call.respond(
            /*(3)!*/verifier.issueChallenge(/*(4)!*/"$publicEndpoint/$PATH_ATTEST")
        )
    }
        /*(5)!*/post(PATH_ATTEST) {
        /*(6)!*/
        val decodedCSR = CertificationRequest.decodeFromDer(call.receive<ByteArray>())
        val result = verifier.verifyAttestation(decodedCSR) {
            /*(7)!*/
            val leafCertificate = signer.sign(
                /*(8)!*/TbsCertificate(
                    /*(9)!*/serialNumber = CryptoRand.nextPositiveAsn1Integer(20),
                    /*(10)!*/publicKey = it.tbsCsr.publicKey,
                    signatureAlgorithm = signer.signatureAlgorithm,
                    validFrom = (Clock.System.now()),
                    validUntil = (Clock.System.now() + 10.days),
                    issuerName = issuerName,
                    subjectName = subjectName,
                )
            ).getOrThrow()
            /*(11)!*/listOf(leafCertificate, caCert)
        }
        /*(12)!*/call.respond(result)
    }
    }
}.start(wait = false)