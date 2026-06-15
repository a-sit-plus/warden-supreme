package at.asitplus.attestation.supreme

import at.asitplus.attestation.FixedTimeClock
import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.TrustedRoot
import at.asitplus.attestation.android.parseHex
import at.asitplus.awesn1.nextPositiveAsn1Integer
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.decodeFromDer
import at.asitplus.signum.indispensable.decodeFromPem
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.CertificationRequest
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.toJcaPublicKey
import at.asitplus.signum.supreme.sign
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.testballoon.matrix.matrixConfig
import at.asitplus.testballoon.matrix.matrixSuite
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.testScope
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.datetime.TimeZone
import org.kotlincrypto.random.CryptoRand
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes
import kotlin.uuid.ExperimentalUuidApi

@OptIn(ExperimentalStdlibApi::class, ExperimentalUuidApi::class)
val TestEnv by matrixSuite(matrixConfig { testConfig = TestConfig.testScope(isEnabled = false) }) {
    if (System.getenv("SUPREME_ENDTOENDTEST") == "true") {
        //starts a KTOR server, because WARDEN cannot run on Android, hence using the MockEngine is no use, because it will
        //fail at runtime

        "Verifier" - {
            val ENDPOINT_CHALLENGE = "/api/v1/challenge"
            val PATH_ATTEST = "/api/v1/attest"
            val ENDPOINT_ATTEST = "http://10.0.2.2:8080$PATH_ATTEST"

            var running: Boolean? = true

            val attestationValidator = AttestationVerifier(
                SupremeConfiguration(
                    AndroidAttestationConfiguration.Builder(
                        AndroidAttestationConfiguration.AppData(
                            "at.asitplus.attestation.supreme.client.test", //automated tests
                            setOf(
                                "a3 e5 5b a9 45 7d e2 90 0f e8 63 03 a5 d5 56 c4 96 b6 91 af ff 2c 0d d5 04 88 be d3 e4 00 cc 6b".parseHex()
                            )
                        )
                    ).enableSoftwareAttestation().disableHardwareAttestation().addSoftwareTrustedRoot(
                        TrustedRoot.PublicKey(
                            CryptoPublicKey.decodeFromPem(
                                "-----BEGIN PUBLIC KEY-----\n" +
                                        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9+hz7A0vjTx6w2x7E6wW8Cy3MlJY\n" +
                                        "+E3HadGEUI8McOFz3VytQgylZWfT+LUKDjTq3CBffGbo1GeBH+leQlFoaw==\n" +
                                        "-----END PUBLIC KEY-----"
                            ).toJcaPublicKey().getOrThrow()
                        )
                    )
                        .build(),
                    IosAttestationConfiguration(
                        IosAttestationConfiguration.AppData(
                            "9CYHJNG644",
                            "at.asitplus.signumtest.iosApp", //to test with real app from ios
                            sandbox = true
                        ),
                    ),
                    clock = object : SupremeConfiguration.Clock {
                        override val timeSource: Clock
                            get() = FixedTimeClock(2025u, 1u, 10u)
                    })
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
                                CertificationRequest.decodeFromDer(src),
                                onPreAttestationError = {
                                    val msg = throwable?.message ?: ""
                                    println(msg)
                                    msg
                                },
                                onAttestationError = { stmt ->
                                    println(stmt.serializeCompact())
                                    stmt.serializeCompact()
                                }) { csr ->
                                println("Successfully attested device ${csr.deviceNameForOid(attestationValidator.genericDeviceNameOID ?: WardenDefaults.OIDs.DEVICE_NAME)}")
                                Signer.Ephemeral {
                                    ec { }
                                }.getOrThrow().let { signer ->
                                    signer.sign(
                                        TbsCertificate(
                                            serialNumber = CryptoRand.nextPositiveAsn1Integer(20),
                                            publicKey = csr.tbsCsr.publicKey,
                                            signatureAlgorithm = signer.signatureAlgorithm,
                                            validFrom = (Clock.System.now()),
                                            validUntil = (Clock.System.now() + 10.days),
                                            issuerName = listOf(
                                                RelativeDistinguishedName(
                                                    AttributeTypeAndValue.CommonName(
                                                        "WARDEN Supreme"
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

            val timeout = 5.minutes
            println("KTOR server started!")
            println("   Waiting $timeout before auto-shutdown!")
            val before = Clock.System.now()

            while (running == true) {
                Thread.sleep(1000)
                if (Clock.System.now() - before > timeout) running = null
            }
            (if (running == null) "Automatically Shutting down after timeout" else "Obeying shutdown request") { server.stop() }
        }
    } else test("Skipping server test") {}
}
