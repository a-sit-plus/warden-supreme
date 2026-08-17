package at.asitplus.warden

import at.asitplus.attestation.fromYamlFile
import at.asitplus.attestation.supreme.AttestationVerifier
import at.asitplus.attestation.supreme.SupremeConfiguration
import at.asitplus.attestation.supreme.decodeAttestationProof
import at.asitplus.attestation.supreme.tbsCsr
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.Asn1Time
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import at.asitplus.signum.supreme.sign
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.warden.collector.shared.DemoAttestation
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.coroutines.delay
import kotlinx.datetime.TimeZone
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.seconds

/**
 * Loads the [SupremeConfiguration] (bundled `supreme.yaml`, or the path in `collector.supremeConfig`).
 * Verification runs on real system time (`clock: system`); the default `verificationTimeOffset`
 * leeway absorbs normal client/server clock skew.
 */
private fun Application.loadVerifier(): AttestationVerifier {
    val configuredPath = environment.config.propertyOrNull("collector.supremeConfig")?.getString()
    val loaded =
        if (configuredPath != null) SupremeConfiguration.fromYamlFile(configuredPath)
        else SupremeConfiguration.fromYamlString(
            this::class.java.classLoader.getResourceAsStream("supreme.yaml")
                ?.readBytes()?.decodeToString()
                ?: error("supreme.yaml not found on the classpath")
        )
    return AttestationVerifier(loaded)
}

fun Application.configureRouting() {
    val verifier = loadVerifier()
    val publicBaseUrl =
        environment.config.propertyOrNull("collector.publicBaseUrl")?.getString() ?: "http://10.0.2.2:8080"
    val attestEndpoint = publicBaseUrl.trimEnd('/') + DemoAttestation.ATTEST_PATH

    routing {
        get("/") {
            call.respondText("WARDEN Supreme collector backend")
        }

        // The app fetches a challenge here; the challenge embeds `attestEndpoint` so the app knows
        // where to submit its proof.
        get(DemoAttestation.CHALLENGE_PATH) {
            call.respond(
                verifier.issueChallenge(
                    attestEndpoint,
                    timeZone = TimeZone.currentSystemDefault(),
                )
            )
        }

        // The app submits the DER-encoded proof (octet-stream). On success we issue a short-lived
        // certificate chain over the attested key and return it as JSON.
        post(DemoAttestation.ATTEST_PATH) {
            val proof = verifier.decodeAttestationProof(call.receive<ByteArray>()).getOrThrow()
            call.respond(
                verifier.verifyAttestation(
                    proof,
                    onPreAttestationError = { throwable?.message },
                    onAttestationError = { statement -> statement.serializeCompact() },
                    certificateIssuer = { received ->
                        val tbsCsr = received.tbsCsr
                        Signer.Ephemeral { ec { } }.getOrThrow().let { signer ->
                            signer.sign(
                                TbsCertificate(
                                    serialNumber = Random.nextBytes(32),
                                    publicKey = tbsCsr.publicKey,
                                    signatureAlgorithm = signer.signatureAlgorithm.toX509SignatureAlgorithm()
                                        .getOrThrow(),
                                    validFrom = Asn1Time(Clock.System.now()),
                                    validUntil = Asn1Time(Clock.System.now() + 10.days),
                                    issuerName = listOf(
                                        RelativeDistinguishedName(
                                            AttributeTypeAndValue.CommonName(Asn1String.UTF8("WARDEN Supreme Collector"))
                                        )
                                    ),
                                    subjectName = tbsCsr.subjectName,
                                )
                            ).map { listOf(it) }.getOrThrow()
                        }
                    },
                )
            )
        }
    }
}
