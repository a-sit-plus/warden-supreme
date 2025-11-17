package at.asitplus.attestation.supreme

import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.TrustedRoot
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.Asn1Time
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequest
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.toJcaPublicKey
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import at.asitplus.signum.supreme.sign
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.testScope
import de.infix.testBalloon.framework.core.testSuite
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.datetime.TimeZone
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes
import kotlin.uuid.ExperimentalUuidApi

@OptIn(ExperimentalStdlibApi::class, ExperimentalUuidApi::class)
val TestEnv by testSuite(testConfig = TestConfig.testScope(isEnabled = true, timeout = 20.minutes)) {

test("verifier") {}

    //starts a KTOR server, because WARDEN cannot run on Android, hence using the MockEngine is no use, because it will
    //fail at runtime
    val STMT_VALIDITY = 15.minutes
    val VERIFICATION_OFFSET = 3.minutes

   "Verifier" - {
        val ENDPOINT_CHALLENGE = "/api/v1/challenge"
        val PATH_ATTEST = "/api/v1/attest"
        val ENDPOINT_ATTEST = "http://10.0.2.2:8080$PATH_ATTEST"

        var running: Boolean? = true

        val attestationValidator = AttestationVerifier(
            AndroidAttestationConfiguration.Builder(
                AndroidAttestationConfiguration.AppData(
                    "at.asitplus.attestation.supreme.client.test", //automated tests
                    listOf(
                        "a3e55ba9457de2900fe86303a5d556c496b691afff2c0dd50488bed3e400cc6b".hexToByteArray(
                            HexFormat.Default
                        )
                    )
                )
            ).enableSoftwareAttestation().disableHardwareAttestation().addSoftwareTrustedRoot(
                TrustedRoot.PublicKey(
                    CryptoPublicKey.decodeFromPem(
                        "-----BEGIN PUBLIC KEY-----\n" +
                                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9+hz7A0vjTx6w2x7E6wW8Cy3MlJY\n" +
                                "+E3HadGEUI8McOFz3VytQgylZWfT+LUKDjTq3CBffGbo1GeBH+leQlFoaw==\n" +
                                "-----END PUBLIC KEY-----"
                    ).getOrThrow().toJcaPublicKey().getOrThrow()
                )
            )
                .attestationStatementValiditySeconds(STMT_VALIDITY.inWholeSeconds)
                .build(),
            IosAttestationConfiguration(
                IosAttestationConfiguration.AppData(
                    "9CYHJNG644",
                    "at.asitplus.signumtest.iosApp", //to test with real app from ios
                    sandbox = true
                ),
                attestationStatementValiditySeconds = STMT_VALIDITY.inWholeSeconds
            ),
            verificationTimeOffset = VERIFICATION_OFFSET,
        )


        val server = embeddedServer(Netty, port = 8080) {
            install(ContentNegotiation) { json() }

            routing {
                get("/shutdown") {
                    test("Received shutdown request") {}
                    call.respondText("Bye!")
                    running = false
                }

                get(ENDPOINT_CHALLENGE) {
                    test("Issuing Challenge") {}
                    call.respond(
                        attestationValidator.issueChallenge(
                            ENDPOINT_ATTEST,
                            timeZone = TimeZone.currentSystemDefault(),
                        )
                    )


                }
                post(PATH_ATTEST) {
                    val src = call.receive<ByteArray>()
                    test("Got Challenge") {}


                    val resp =
                        attestationValidator.verifyAttestation(
                            Pkcs10CertificationRequest.decodeFromDer(src),
                            onPreAttestationError = {
                                val msg = throwable?.message ?: ""
                                println(msg)
                                msg
                            },
                            onAttestationError = { stmt ->
                                println(stmt.serializeCompact())
                                stmt.serializeCompact()
                            }) { csr ->
                            println("Successfully attested device ${csr.deviceName}")
                            Signer.Ephemeral {
                                ec { }
                            }.getOrThrow().let { signer ->
                                signer.sign(
                                    TbsCertificate(
                                        serialNumber = Random.nextBytes(32),
                                        publicKey = csr.tbsCsr.publicKey,
                                        signatureAlgorithm = signer.signatureAlgorithm.toX509SignatureAlgorithm()
                                            .getOrThrow(),
                                        validFrom = Asn1Time(Clock.System.now()),
                                        validUntil = Asn1Time(Clock.System.now() + 10.days),
                                        issuerName = listOf(
                                            RelativeDistinguishedName(
                                                AttributeTypeAndValue.CommonName(
                                                    Asn1String.UTF8(
                                                        "WARDEN Supreme"
                                                    )
                                                )
                                            )
                                        ),
                                        subjectName = csr.tbsCsr.subjectName,
                                    )
                                ).map { listOf(it) }.getOrThrow()
                            }
                        }
                    call.respond(resp)
                }

            }
        }.start(wait = false)

        var timeout = 5.minutes
        println("KTOR server started!")
        println("   Waiting $timeout before auto-shutdown!")
        val before = Clock.System.now()

        while (running == true) {
            Thread.sleep(1000)
            if (Clock.System.now() - before > timeout) running = null
        }
        (if (running == null) "Automatically Shutting down after timeout" else "Obeying shutdown request") { server.stop() }
    }
}