package at.asitplus.attestation.supreme

import at.asitplus.attestation.AttestationResult
import at.asitplus.attestation.IOSAttestationConfiguration
import at.asitplus.attestation.Warden
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.openid.odcJsonSerializer
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.Asn1Time
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.io.InstantLongSerializer
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequest
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.toJcaPublicKey
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import at.asitplus.signum.supreme.sign
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
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
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.lang.System.exit
import kotlin.random.Random
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsSignature
import at.asitplus.wallet.lib.jws.VerifyJwsSignatureFun
import io.kotest.property.Gen
import kotlinx.serialization.SerialName
import kotlin.reflect.typeOf
import kotlin.time.Duration.Companion.hours
import kotlin.time.Instant

@OptIn(ExperimentalStdlibApi::class, ExperimentalUuidApi::class)
class TestEnv : FreeSpec({

    //starts a KTOR server, because WARDEN cannot run on Android, hence using the MockEngine is no use, because it will
    //fail at runtime
    "startServer" {
        val ENDPOINT_CHALLENGE = "/api/v1/challenge"

        val ENDPOINT_WAA = "/api/v1/waa"
        val ENDPOINT_WUA = "/api/v1/wua"

        val PATH_ATTEST = "/api/v1/attest"
        val ENDPOINT_ATTEST = "http://10.0.2.2:8080$PATH_ATTEST"
        val PROOF_OID = ObjectIdentifier(Uuid.parse("c893b702-28f6-4c50-8578-d1d7a1580729"))
        val NONCE = Random.nextBytes(16)

        val jwtKey = EphemeralKeyWithoutCert()
        val jwtPubKey = jwtKey.publicKey

        val signJwtFun: SignJwtFun<WalletAttestationToken>? = SignJwt(
            jwtKey,
            JwsHeaderNone()
        )

        var running = true

        val attestationValidator = AttestationValidator(
            Warden(
                AndroidAttestationConfiguration.Builder(
                    AndroidAttestationConfiguration.AppData(
                        "at.asitplus.wallet.app.android", //automated tests
                        listOf(
                            "90f18fc8514fed2ec9e1f4924cc5de0ef8d7829661a77b923ac2eb5ae3e4a0f2".hexToByteArray(
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
                ).build(),
                IOSAttestationConfiguration(
                    IOSAttestationConfiguration.AppData(
                        "9CYHJNG644",
                        "at.asitplus.signumtest.iosApp", //to test with real app from ios
                        sandbox = true
                    )
                ), Clock.System, verificationTimeOffset = 3.minutes
            ),
            attestationProofOID = PROOF_OID,
        ) { it.contentEquals(NONCE) }


        val server = embeddedServer(Netty, port = 8080) {
            install(ContentNegotiation) {
                json()
            }

            routing {
                get("/shutdown") {
                    call.respondText("Bye!")
                    running = false
                }

                get(ENDPOINT_CHALLENGE) {

                    println("Issuing Challenge")
                    call.respondText(
                        Json.encodeToString(
                            attestationValidator.issueChallenge(
                                NONCE,
                                10.minutes,
                                ENDPOINT_ATTEST,
                                timeOffset = -5.minutes
                            )
                        ), contentType = ContentType.Application.Json
                    )
                }

                post(ENDPOINT_WAA) {
                    println("Issuing WAA")

                    val src = call.receive<ByteArray>()

                    val resp =
                        attestationValidator.verifyKeyAttestation(Pkcs10CertificationRequest.decodeFromDer(src)) { csr ->
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
                        }

                    when (resp) {
                        is AttestationResponse.Success -> {
                            val jwt = signJwtFun?.invoke(
                                type = null,
                                payload = WalletAttestationToken(
                                    issuer = "TestEnv-Issuing",
                                    type = "oauth-client-attestation-pop+jwt",
                                    expiration = Clock.System.now() + 1.hours,
                                    eudiWalletInfo = dummyGeneralInfo
                                ),
                                serializer = WalletAttestationToken.serializer()
                            )
                            call.respondText(jwt?.getOrThrow()?.serialize()!!)
                        }

                        is AttestationResponse.Failure -> {
                            call.respondText("Error!")
                        }
                    }


                }

                post(ENDPOINT_WUA) {
                    val src = call.receive<String>()
                    val token = JwsSigned.deserialize<WalletAttestationToken>(
                        it = src,
                        deserializationStrategy = WalletAttestationToken.serializer(),
                        json = odcJsonSerializer
                    )
                    if (VerifyJwsSignature().invoke(token.getOrThrow(), jwtPubKey)) {
                        val jwt = signJwtFun?.invoke(
                            type = null,
                            payload = WalletAttestationToken(
                                issuer = "TestEnv-Issuing",
                                type = "oauth-client-attestation-pop+jwt",
                                expiration = Clock.System.now() + 1.hours,
                                eudiWalletInfo = dummyGeneralInfo,
                                wscdInfo = dummyWscdInfo
                            ),
                            serializer = WalletAttestationToken.serializer()
                        )
                        call.respondText(jwt?.getOrThrow()?.serialize()!!)
                    }
                }

                post(PATH_ATTEST) {
                    val src = call.receive<ByteArray>()

                    val resp =
                        attestationValidator.verifyKeyAttestation(Pkcs10CertificationRequest.decodeFromDer(src)) { csr ->
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
                        }

                    call.respondText(Json.encodeToString(resp), contentType = ContentType.Application.Json)
                }
            }
        }.start(wait = false)
        println("KTOR server started!")
        while (running) {
            Thread.sleep(500)
        }
    }
})

@Serializable
class WalletAttestationToken(
    @SerialName("iss")
    val issuer: String? = null,

    @SerialName("typ")
    val type: String,

    @SerialName("aud")
    val audience: String? = null,

    @SerialName("exp")
    @Serializable(with = InstantLongSerializer::class)
    val expiration: kotlinx.datetime.Instant? = null,

    @SerialName("jti")
    val jwtId: String? = null,

    @SerialName("eudi_wallet_info")
    val eudiWalletInfo: GeneralInfo,

    @SerialName("wscd_info")
    val wscdInfo: WscdInfo? = null
)

@Serializable
data class GeneralInfo(
    @SerialName("wallet_provider_name") val walletProviderName: String,
    @SerialName("wallet_solution_id") val walletSolutionId: String,
    @SerialName("wallet_solution_version") val walletSolutionVersion: String,
    @SerialName("wallet_solution_certification_information") val walletSolutionCertificationInformation: String
)

@Serializable
data class WscdInfo(
    @SerialName("wscd_type") val wscdType: String,
    @SerialName("wscd_certification_information") val wscdCertificationInformation: String,
    @SerialName("wscd_attack_resistance") val wscdAttackResistance: Int,
)

val dummyGeneralInfo = GeneralInfo(
    walletProviderName = "TestEnv",
    walletSolutionId = "1234",
    walletSolutionVersion = "0.1",
    walletSolutionCertificationInformation = ""
)

val dummyWscdInfo = WscdInfo(
    wscdType = "LOCAL_INTERNAL",
    wscdCertificationInformation = "",
    wscdAttackResistance = 2
)

