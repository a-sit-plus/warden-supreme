package at.asitplus.attestation.supreme

import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.signum.indispensable.CryptoPublicKey
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
import kotlinx.datetime.TimeZone
import kotlinx.serialization.json.Json
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

@OptIn(ExperimentalStdlibApi::class, ExperimentalUuidApi::class)
class TestEnv : FreeSpec({

    //starts a KTOR server, because WARDEN cannot run on Android, hence using the MockEngine is no use, because it will
    //fail at runtime
    val STMT_VALIDITY = 15.minutes
    val VERIFICATION_OFFSET = 3.minutes
    "startServer" {
        val ENDPOINT_CHALLENGE = "/api/v1/challenge"
        val PATH_ATTEST = "/api/v1/attest"
        val ENDPOINT_ATTEST = "http://10.0.2.2:8080$PATH_ATTEST"
        val PROOF_OID = ObjectIdentifier(Uuid.parse("c893b702-28f6-4c50-8578-d1d7a1580729"))
        val NONCE = Random.nextBytes(16)

        var running = true

        val attestationValidator = AttestationValidator(
            AndroidAttestationConfiguration.Builder(
                AndroidAttestationConfiguration.AppData(
                    "at.asitplus.attestation.supreme.client.test", //automated tests
                    listOf(
                        "a3e55ba9457de2900fe86303a5d556c496b691afff2c0dd50488bed3e400cc6b".hexToByteArray(
                            HexFormat.Default
                        )
                    )
                )
            ).enableSoftwareAttestation().disableHardwareAttestation().addSoftwareAttestationTrustAnchor(
                CryptoPublicKey.decodeFromPem(
                    "-----BEGIN PUBLIC KEY-----\n" +
                            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9+hz7A0vjTx6w2x7E6wW8Cy3MlJY\n" +
                            "+E3HadGEUI8McOFz3VytQgylZWfT+LUKDjTq3CBffGbo1GeBH+leQlFoaw==\n" +
                            "-----END PUBLIC KEY-----"
                ).getOrThrow().toJcaPublicKey().getOrThrow()
            ).ingoreLeafValidity()
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
            attestationProofOID = PROOF_OID,
            Clock.System, verificationTimeOffset = VERIFICATION_OFFSET,
        ) {
            if (it.contentEquals(NONCE)) ChallengeValidationResult.Success
            else ChallengeValidationResult.Failure(null)
        }


        val server = embeddedServer(Netty, port = 8080) {
            install(ContentNegotiation) {
                json()
            }

            routing {
                get("/shutdown") {
                    println("Shutting down...")
                    call.respondText("Bye!")
                    running = false
                }

                get(ENDPOINT_CHALLENGE) {

                    println("Issuing Challenge")
                    call.respondText(
                        Json.encodeToString(
                            attestationValidator.issueChallenge(
                                NONCE,
                                STMT_VALIDITY,
                                timeZone = TimeZone.currentSystemDefault(),
                                ENDPOINT_ATTEST,
                                timeOffset = VERIFICATION_OFFSET
                            )
                        ), contentType = ContentType.Application.Json
                    )
                }
                post(PATH_ATTEST) {
                    val src = call.receive<ByteArray>()
                    val resp =
                        attestationValidator.verifyKeyAttestation(
                            Pkcs10CertificationRequest.decodeFromDer(src),
                            onPreAttestationError = {
                                val msg= this.throwable?.message?:""
                                println(msg)
                                msg
                            },
                            onAttestationError = { stmt ->
                                println(stmt.serializeCompact())
                                stmt.serializeCompact()
                            }) { csr ->
                            Signer.Ephemeral {
                                ec { }
                            }.getOrThrow().let { signer ->
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
                                                        "WARDEN Supreme"
                                                    )
                                                )
                                            )
                                        ),
                                        subjectName = csr.tbsCsr.subjectName,
                                    )
                                ).map { listOf(it) }
                            }
                        }
                    call.respondText(Json.encodeToString(resp), contentType = ContentType.Application.Json)
                }
            }
        }.start(wait = false)
        println("KTOR server started!")
        val before = Clock.System.now()

        while (running) {
            Thread.sleep(1000)
            if(Clock.System.now()-before>5.minutes) running = false
        }
        server.stop()
    }
})