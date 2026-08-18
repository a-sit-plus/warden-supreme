package at.asitplus.warden

import at.asitplus.attestation.AttestationResult
import at.asitplus.attestation.android.VerifiedBootKey
import at.asitplus.attestation.android.parseHex
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
import at.asitplus.warden.collector.shared.CollectorPolicy
import at.asitplus.warden.collector.shared.DemoAttestation
import io.ktor.server.application.*
import io.ktor.http.HttpHeaders
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
private fun Application.loadConfiguration(): SupremeConfiguration {
    val configuredPath = environment.config.propertyOrNull("collector.supremeConfig")?.getString()
    return if (configuredPath != null) SupremeConfiguration.fromYamlFile(configuredPath)
    else SupremeConfiguration.fromYamlString(
        this::class.java.classLoader.getResourceAsStream("supreme.yaml")
            ?.readBytes()?.decodeToString()
            ?: error("supreme.yaml not found on the classpath")
    )
}

private val grapheneOsVerifiedBootKeys = setOf(
    "d8f879d10419eddc9fcda6280718be763f6bf12299e1f72df3ea8ad8a8eb7f80",
    "55a2d44103e56d5ec65496399c417987ba77730e6488fc60ba058d09fc3caee3",
    "141d7fc32af7958a416f2661b37cf6f27bfb376fb5ce616aeaa27a82c7a04f74",
    "4e8ee8f717754052198ca6d2d3aaa232e2461b4293c0d6f297e519cc778de093",
    "3f7415ea26f5df5b14ea6d153256071a7a1af9ce7b0970b7311cc463c7ea02c7",
    "0508de44ee00bfb49ece32c418af1896391abde0f05b64f41bc9a2dfb589445b",
    "af4d2c6e62be0fec54f0271b9776ff061dd8392d9f51cf6ab1551d346679e24c",
    "55d3c2323db91bb91f20d38d015e85112d038f6b6b5738fe352c1a80dba57023",
    "f729cab861da1b83fdfab402fc9480758f2ae78ee0b61c1f2137dd1ab7076e86",
    "9e6a8f3e0d761a780179f93acd5721ba1ab7c8c537c7761073c0a754b0e932de",
    "096b8bd6d44527a24ac1564b308839f67e78202185cbff9cfdcb10e63250bc5e",
    "896db2d09d84e1d6bb747002b8a114950b946e5825772a9d48ba7eb01d118c1c",
    "cd7479653aa88208f9f03034810ef9b7b0af8a9d41e2000e458ac403a2acb233",
    "ee0c9dfef6f55a878538b0dbf7e78e3bc3f1a13c8c44839b095fe26dd5fe2842",
    "94df136e6c6aa08dc26580af46f36419b5f9baf46039db076f5295b91aaff230",
    "508d75dea10c5cbc3e7632260fc0b59f6055a8a49dd84e693b6d8899edbb01e4",
    "bc1c0dd95664604382bb888412026422742eb333071ea0b2d19036217d49182f",
    "3efe5392be3ac38afb894d13de639e521675e62571a8a9b3ef9fc8c44fd17fa1",
    "08c860350a9600692d10c8512f7b8e80707757468e8fbfeea2a870c0a83d6031",
    "439b76524d94c40652ce1bf0d8243773c634d2f99ba3160d8d02aa5e29ff925c",
    "f0a890375d1405e62ebfd87e8d3f475f948ef031bbf9ddd516d5f600a23677e8",
).mapTo(linkedSetOf()) { VerifiedBootKey.Digest(it.parseHex()) }

internal fun SupremeConfiguration.forCollectorPolicy(policy: CollectorPolicy): SupremeConfiguration {
    val base = requireNotNull(android) { "Collector requires an Android attestation configuration" }
    val configured = when (policy) {
        CollectorPolicy.DEFAULT -> base
        CollectorPolicy.OLD_FACTORY_CERTIFICATES -> base.copy(enforceFactoryProvisionedChainValidity = false)
        CollectorPolicy.UNLOCKED_BOOTLOADER -> base.copy(
            enforceFactoryProvisionedChainValidity = false,
            allowBootloaderUnlock = true,
        )
        CollectorPolicy.GRAPHENE_OS -> base.copy(
            enforceFactoryProvisionedChainValidity = false,
            allowBootloaderUnlock = false,
            requireStrongBox = true,
            verifiedBootKeys = base.verifiedBootKeys + grapheneOsVerifiedBootKeys,
        )
        CollectorPolicy.STRONGBOX_ONLY -> base.copy(requireStrongBox = true)
    }
    return ios?.let {
        SupremeConfiguration(
            android = configured,
            ios = it,
            clock = clock,
            verificationTimeOffset = verificationTimeOffset,
            attestationProofOID = attestationProofOID,
            genericDeviceNameOID = genericDeviceNameOID,
            defaultKeyConstraints = defaultKeyConstraints,
            dataAuth = dataAuthentication,
            toBeAttestedAttributes = toBeAttestedAttributes,
            maxAttestationPayloadBytes = maxAttestationPayloadBytes,
        )
    } ?: SupremeConfiguration(
        android = configured,
        clock = clock,
        verificationTimeOffset = verificationTimeOffset,
        attestationProofOID = attestationProofOID,
        genericDeviceNameOID = genericDeviceNameOID,
        defaultKeyConstraints = defaultKeyConstraints,
        dataAuth = dataAuthentication,
        toBeAttestedAttributes = toBeAttestedAttributes,
        maxAttestationPayloadBytes = maxAttestationPayloadBytes,
    )
}

fun Application.configureRouting() {
    val configuration = loadConfiguration()
    val verifiers = CollectorPolicy.entries.associateWith { AttestationVerifier(configuration.forCollectorPolicy(it)) }
    val publicBaseUrl = System.getenv("BASE_URL")?.ifBlank { null }
        ?: System.getenv("SLIPLANE_DOMAIN")?.ifBlank { null }?.let { "https://$it" }
        ?: environment.config.propertyOrNull("collector.publicBaseUrl")?.getString()
        ?: "http://10.0.2.2:8080"
    val outputDir = File(
        System.getenv("OUTPUT_DIR")?.ifBlank { null }
            ?: environment.config.propertyOrNull("collector.outputDir")?.getString()
            ?: "./collected-proofs"
    )
    val store = CollectorStore(outputDir)
    monitor.subscribe(ApplicationStopped) { store.close() }
    val collectorVersionCode = this::class.java.classLoader.getResource("collector-version.txt")
        ?.readText()?.trim() ?: error("collector-version.txt not found on the classpath")

    routing {

        get("/health") {
            call.respondText("OK")
        }

        get(DemoAttestation.VERSION_PATH) {
            call.respondText(collectorVersionCode)
        }

        CollectorPolicy.entries.forEach { policy ->
            val verifier = verifiers.getValue(policy)
            get(policy.challengePath) {
                call.respond(
                    verifier.issueChallenge(
                        publicBaseUrl.trimEnd('/') + policy.attestPath,
                        timeZone = TimeZone.currentSystemDefault(),
                    )
                )
            }

            // The app submits the DER-encoded proof (octet-stream). We verify, persist the collected
            // attestation (WARDEN debug statement + metadata), and — on success — issue a short-lived
            // certificate chain over the attested key and return it as JSON.
            post(policy.attestPath) {
                val proofBytes = call.receive<ByteArray>()
                log.info("Received attestation proof; policy={}; bytes={}", policy.name, proofBytes.size)
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
                            )
                            .map { listOf(it) }.getOrThrow()
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
        get("/collector-apk-qr.svg") {
            call.respondResource("collector-apk-qr.svg")
        }
        get(DemoAttestation.DOWNLOAD_PATH) {
            call.respondResource("collector.apk")
        }
        get(DEBUG_STATEMENTS_ARCHIVE_PATH) {
            call.response.header(HttpHeaders.ContentDisposition, "attachment; filename=\"debug-statements.zip\"")
            call.respondFile(store.debugStatementsArchive())
        }

        // Downloads (chain.der, proof.der, debug-statement.json, attestation.json) are the files
        // written per submission under the output directory — served directly, no download routes.
        staticFiles("/files", outputDir)
    }
}
