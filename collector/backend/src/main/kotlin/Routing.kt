package at.asitplus.warden

import at.asitplus.attestation.AttestationResult
import at.asitplus.attestation.fromYamlFile
import at.asitplus.attestation.supreme.AttestationResponse
import at.asitplus.attestation.supreme.AttestationVerifier
import at.asitplus.attestation.supreme.SupremeConfiguration
import at.asitplus.attestation.supreme.WardenDefaults
import at.asitplus.attestation.supreme.decodeAttestationProof
import at.asitplus.attestation.supreme.deviceNameForOid
import at.asitplus.attestation.supreme.tbsCsr
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.AndroidKeystoreAttestation
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.Asn1Time
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.pki.X509Certificate as SignumX509Certificate
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import at.asitplus.signum.supreme.sign
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.warden.collector.shared.DemoAttestation
import io.ktor.server.application.*
import io.ktor.server.html.respondHtml
import io.ktor.server.http.content.staticFiles
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.datetime.TimeZone
import java.io.File
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days

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
    val publicBaseUrl = System.getenv("BASE_URL")?.ifBlank { null }
        ?: System.getenv("SLIPLANE_DOMAIN")?.ifBlank { null }?.let { "https://$it" }
        ?: environment.config.propertyOrNull("collector.publicBaseUrl")?.getString()
        ?: "http://10.0.2.2:8080"
    val attestEndpoint = publicBaseUrl.trimEnd('/') + DemoAttestation.ATTEST_PATH
    val outputDir = File(
        System.getenv("OUTPUT_DIR")?.ifBlank { null }
            ?: environment.config.propertyOrNull("collector.outputDir")?.getString()
            ?: "./collected-proofs"
    )
    val store = CollectorStore(outputDir)
    val collectorVersionCode = this::class.java.classLoader.getResource("collector-version.txt")
        ?.readText()?.trim() ?: error("collector-version.txt not found on the classpath")

    routing {

        get("/health") {
            call.respondText("OK")
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

        get(DemoAttestation.VERSION_PATH) {
            call.respondText(collectorVersionCode)
        }

        // The app submits the DER-encoded proof (octet-stream). We verify, persist the collected
        // attestation (WARDEN debug statement + metadata), and — on success — issue a short-lived
        // certificate chain over the attested key and return it as JSON.
        post(DemoAttestation.ATTEST_PATH) {
            val proofBytes = call.receive<ByteArray>()
            val proof = verifier.decodeAttestationProof(proofBytes).getOrThrow()

            val submittedAt = Clock.System.now().toEpochMilliseconds()
            val deviceName = catchingUnwrapped {
                proof.tbsCsr.deviceNameForOid(verifier.genericDeviceNameOID ?: WardenDefaults.OIDs.DEVICE_NAME)
            }.getOrNull()

            // The WARDEN debug statement for this submission — captured on either outcome.
            var statement: String? = null

            val response = verifier.verifyAttestation(
                proof,
                onPreAttestationError = { throwable?.message },
                onAttestationError = { debugInfo ->
                    catchingUnwrapped { statement = debugInfo.serializeCompact() }
                    explanation
                },
                onAttestationSuccess = { _ ->
                    // No debug statement is auto-built on success — build one from the verified chain.
                    catchingUnwrapped {
                        val verified = this as AttestationResult.Android.Verified
                        val nonce = verified.androidAttestationExtension.attestationChallenge
                        val chain = verified.attestationCertificateChain
                            .map { SignumX509Certificate.decodeFromDer(it.encoded) }
                        statement = verifier.makoto
                            .collectDebugInfo(AndroidKeystoreAttestation(chain), nonce)
                            .serializeCompact()
                    }
                },
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

            val verified = response is AttestationResponse.Success
            val result = if (verified) "Verified"
            else (response as AttestationResponse.Failure).let { "${it.kind}: ${it.explanation ?: "attestation failed"}" }

            // Extract columns and emit all download artifacts to disk now — the report and downloads
            // just read files afterwards (no per-request regeneration).
            store.collect(
                submittedAtEpochMs = submittedAt,
                deviceName = deviceName,
                result = result,
                verified = verified,
                statement = statement,
                proofBytes = proofBytes,
            )

            call.respond(response)
        }

        // Human-readable report of everything collected so far.
        get("/") {
            val records = store.list()
            call.respondHtml { renderCollectedReport(records) }
        }

        get("/favicon.png") {
            call.respondResource("warden.png")
        }
        get("/logo.png") {
            call.respondResource("supreme-horz.png")
        }
        get("/collector.css") {
            call.respondResource("collector.css")
        }
        get(DemoAttestation.DOWNLOAD_PATH) {
            call.respondRedirect(
                "https://github.com/a-sit-plus/warden-supreme/releases/download/" +
                    "collector-v$collectorVersionCode/collector.apk"
            )
        }

        // Downloads (chain.der, proof.der, debug-statement.json, attestation.json) are the files
        // written per submission under the output directory — served directly, no download routes.
        staticFiles("/files", outputDir)
    }
}
