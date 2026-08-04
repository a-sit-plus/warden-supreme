package at.asitplus.attestation.supreme

import at.asitplus.attestation.FixedTimeClock
import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.TrustedRoot
import at.asitplus.attestation.android.parseHex
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.Asn1Time
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequest
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.toJcaPublicKey
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import at.asitplus.signum.supreme.sign
import at.asitplus.signum.supreme.sign.Signer
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.testScope
import at.asitplus.testballoon.matrix.*
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

private data class AuthenticationScenario(
    val authentication: DataAuthentication,
    val expectedAttributes: List<Primitive>?,
)

private val authenticationScenarios = mapOf(
    "signed-no-attributes" to AuthenticationScenario(DataAuthentication.Signature, null),
    "hashed-no-attributes" to AuthenticationScenario(DataAuthentication.Hash(Digest.SHA256), null),
    "signed-optional-present" to AuthenticationScenario(DataAuthentication.Signature, listOf("required", 42)),
    "signed-optional-omitted" to AuthenticationScenario(DataAuthentication.Signature, listOf("required", null)),
    "hashed-optional-present" to AuthenticationScenario(DataAuthentication.Hash(Digest.SHA256), listOf("required", 42)),
    "hashed-optional-omitted" to AuthenticationScenario(DataAuthentication.Hash(Digest.SHA256), listOf("required", null)),
    "signed-required-omitted" to AuthenticationScenario(DataAuthentication.Signature, listOf(null, 42)),
    "hashed-required-omitted" to AuthenticationScenario(DataAuthentication.Hash(Digest.SHA256), listOf(null, 42)),
    "signed-all-omitted" to AuthenticationScenario(DataAuthentication.Signature, listOf(null, null)),
    "hashed-all-omitted" to AuthenticationScenario(DataAuthentication.Hash(Digest.SHA256), listOf(null, null)),
)

private val requestedAttributes = AttestationChallenge.CertificationRequestAttributeAttestationDescriptor(
    ObjectIdentifier("1.3.6.1.4.1.60387.1"),
    listOf(
        AttestationChallenge.AttributeAttestationDescriptor("required", PrimitiveType.STRING),
        AttestationChallenge.AttributeAttestationDescriptor("optional", PrimitiveType.INT, required = false),
    ),
)

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
                            ).getOrThrow().toJcaPublicKey().getOrThrow()
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

            suspend fun verify(
                proof: AttestationProof,
                scenario: AuthenticationScenario,
            ) = attestationValidator.verifyAttestation(
                proof,
                onPreAttestationError = {
                    val msg = throwable?.message ?: ""
                    println(msg)
                    msg
                },
                onAttestationError = { statement ->
                    println(statement.serializeCompact())
                    statement.serializeCompact()
                },
                additionalVerifications = { received, _ ->
                    val actual = toBeAttestedAttributes?.let { requested ->
                        val tbsCsr = received.tbsCsr
                        val encoded = tbsCsr.attributes.singleOrNull { it.oid == requested.oid }
                            ?.value?.singleOrNull()?.asSequence()
                        AttestedAttributes(encoded).parsedAttributesBy(this)
                    }
                    if (actual == scenario.expectedAttributes) null
                    else AttestationResponse.Failure(
                        AttestationResponse.Failure.Type.CONTENT,
                        "Expected ${scenario.expectedAttributes}, got $actual",
                    )
                },
                certificateIssuer = { received ->
                    val tbsCsr = received.tbsCsr
                    println("Successfully attested device ${tbsCsr.deviceNameForOid(attestationValidator.genericDeviceNameOID ?: WardenDefaults.OIDs.DEVICE_NAME)}")
                    Signer.Ephemeral { ec { } }.getOrThrow().let { signer ->
                        signer.sign(
                            TbsCertificate(
                                serialNumber = Random.nextBytes(32),
                                publicKey = tbsCsr.publicKey,
                                signatureAlgorithm = signer.signatureAlgorithm.toX509SignatureAlgorithm().getOrThrow(),
                                validFrom = Asn1Time(Clock.System.now()),
                                validUntil = Asn1Time(Clock.System.now() + 10.days),
                                issuerName = listOf(
                                    RelativeDistinguishedName(
                                        AttributeTypeAndValue.CommonName(Asn1String.UTF8("WARDEN Supreme"))
                                    )
                                ),
                                subjectName = tbsCsr.subjectName,
                            )
                        ).map { listOf(it) }.getOrThrow()
                    }
                },
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
                    get("$ENDPOINT_CHALLENGE/{scenario}") {
                        val scenarioName = requireNotNull(call.parameters["scenario"])
                        val scenario = requireNotNull(authenticationScenarios[scenarioName])
                        call.respond(
                            attestationValidator.issueChallenge(
                                "$ENDPOINT_ATTEST/$scenarioName",
                                timeZone = TimeZone.currentSystemDefault(),
                                keyConstraints = WardenDefaults.KeyConstraints.p256Signer,
                                attestableAttributes = scenario.expectedAttributes?.let { requestedAttributes },
                                dataAuth = scenario.authentication,
                            )
                        )
                    }
                    post(PATH_ATTEST) {
                        val src = call.receive<ByteArray>()
                        test("Got Challenge") {}
                        call.respond(
                            verify(
                                AttestationProof.Signed(Pkcs10CertificationRequest.decodeFromDer(src)),
                                AuthenticationScenario(DataAuthentication.Signature, null),
                            )
                        )
                    }
                    post("$PATH_ATTEST/{scenario}") {
                        val scenarioName = requireNotNull(call.parameters["scenario"])
                        val scenario = requireNotNull(authenticationScenarios[scenarioName])
                        val src = call.receive<ByteArray>()
                        val proof = AttestationProof.decodeFromDer(src).getOrThrow()
                        call.respond(verify(proof, scenario))
                    }

                }
            }.start(wait = false)

            val timeout = 15.minutes
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
