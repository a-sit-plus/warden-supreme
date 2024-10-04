import at.asitplus.attestation.IOSAttestationConfiguration
import at.asitplus.attestation.Warden
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.Asn1Time
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequest
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import at.asitplus.signum.supreme.sign
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.veritatis.Sanctor
import io.kotest.common.runBlocking
import io.kotest.core.spec.style.FreeSpec
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.datetime.Clock
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.random.Random
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes

@OptIn(ExperimentalStdlibApi::class)
class TestEnv : FreeSpec({

    //starts a KTOR server, because WARDEN cannot run on Android, hence using the MockEngine is no use, because it will
    //fail at runtime
    "startServer" {
        println("KTOR server started!")

        val ENDPOINT_CHALLENGE = "/api/v1/challenge"
        val PATH_ATTEST = "/api/v1/attest"
        val ENDPOINT_ATTEST = "http://10.0.2.2:8080$PATH_ATTEST"
        val PROOF_OID = ObjectIdentifier("2.25.123456789")
        val NONCE = Random.nextBytes(16)

        val sanctor = Sanctor(
            Warden(
                AndroidAttestationConfiguration.Builder(
                    AndroidAttestationConfiguration.AppData(
                        "at.asitplus.veritatis.servus.test",
                        listOf(
                            "941A4513A3027563D3A6EA48EEE85BA45EB9F69CEEA19EF0EBB17F100BFC8878".hexToByteArray(
                                HexFormat.UpperCase
                            )
                        )
                    )
                ).enableSoftwareAttestation().disableHardwareAttestation().build(),
                IOSAttestationConfiguration(
                    IOSAttestationConfiguration.AppData(
                        "9CYHJNG644",
                        "at.asitplus.signumtest.iosApp",
                        sandbox = true
                    )
                ), Clock.System, verificationTimeOffset = 5.minutes
            ),
            attestationProofOID = PROOF_OID,
        ) { it.contentEquals(NONCE) }

        embeddedServer(Netty, port = 8080) {
            install(ContentNegotiation) {
                json()
            }
            routing {
                get(ENDPOINT_CHALLENGE) {

                    call.respondText(Json.encodeToString(sanctor.issueChallenge(NONCE, 10.minutes, ENDPOINT_ATTEST, timeOffset = -5.minutes)), contentType = ContentType.Application.Json)
                }
                post(PATH_ATTEST) {
                    val resp =
                        sanctor.verifyKeyAttestation(Pkcs10CertificationRequest.decodeFromDer(call.receive<ByteArray>())) { csr ->
                            Signer.Ephemeral {
                                ec { }
                            }.getOrThrow().let { signer ->
                                runBlocking {
                                    signer.sign(
                                        TbsCertificate(
                                            serialNumber = Random.nextBytes(32),
                                            publicKey = signer.publicKey,
                                            signatureAlgorithm = signer.signatureAlgorithm.toX509SignatureAlgorithm()
                                                .getOrThrow(),
                                            validFrom = Asn1Time(Clock.System.now()),
                                            validUntil = Asn1Time(Clock.System.now() + 10.days),
                                            issuerName = listOf(
                                                RelativeDistinguishedName(
                                                    AttributeTypeAndValue.CommonName(
                                                        Asn1String.UTF8(
                                                            "SANCTOR"
                                                        )
                                                    )
                                                )
                                            ),
                                            subjectName = csr.tbsCsr.subjectName,
                                        )
                                    ).map { listOf(it) }
                                }
                            }
                        }

                    call.respondText(Json.encodeToString(resp), contentType = ContentType.Application.Json)
                }
            }
        }.start(wait = true)
    }
})