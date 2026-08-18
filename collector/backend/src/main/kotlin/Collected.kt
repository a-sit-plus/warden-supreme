@file:OptIn(ExperimentalTime::class)

package at.asitplus.warden

import at.asitplus.attestation.WardenDebugAttestationStatement
import at.asitplus.attestation.AttestationResult
import at.asitplus.attestation.KeyAttestation
import at.asitplus.attestation.android.*
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.AndroidKeystoreAttestation
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.leaf
import at.asitplus.warden.collector.shared.DemoAttestation
import at.asitplus.warden.collector.shared.androidAttestationJson
import kotlinx.html.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.selects.select
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import org.slf4j.LoggerFactory
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.random.Random
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

private val json = Json { ignoreUnknownKeys = true }
private val prettyJson = Json { prettyPrint = true }
private val logger = LoggerFactory.getLogger(CollectorStore::class.java)
const val DEBUG_STATEMENTS_ARCHIVE_PATH = "/debug-statements.zip"

/**
 * One collected attestation, fully pre-extracted at collection time so the report never re-parses.
 * Column values are extracted once (each defensively) from the attestation; the downloadable
 * artifacts (proof.der, chain.der, debug-statement.json, attestation.json) are written to the same
 * per-submission directory and served statically. [attestationJson] backs the collapsible tree.
 */
@Serializable
data class CollectedRecord(
    val submittedAtEpochMs: Long,
    val deviceName: String? = null,
    val result: String,
    val verified: Boolean,
    val securityLevel: String? = null,
    val osAndPatch: String? = null,
    val avb: String? = null,
    val packageName: String? = null,
    val packageVersion: String? = null,
    val certValidityStart: String,
    val certValidityEnd: String,
    val provisioning: String? = null,
    val createdOnDevice: String? = null,
    val attestationJson: JsonElement? = null,
    val hasChain: Boolean = false,
    val hasStatement: Boolean = false,
    val hasAttestationJson: Boolean = false,
)

/** Filesystem store: one directory per collected attestation under [dir]. */
class CollectorStore(private val dir: File) : AutoCloseable {
    private sealed interface ArchiveCommand {
        data object StatementsChanged : ArchiveCommand
        data class Get(val result: CompletableDeferred<File>) : ArchiveCommand
    }

    private val debugStatementsArchive = File(dir, DEBUG_STATEMENTS_ARCHIVE_PATH.removePrefix("/"))
    private val archiveCommands = Channel<ArchiveCommand>(Channel.UNLIMITED)
    private val archiveRequests = Channel<Unit>(Channel.CONFLATED)
    private val archiveScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    init {
        dir.mkdirs()
        runBlocking { replayStoredStatements() }
        archiveScope.launch { runArchiveWorker() }
    }

    /**
     * Writes all artifacts for one submission to `<dir>/<id>/` and returns the id. Extraction and
     * file emission happen once, here — the report and downloads just read files afterwards.
     */
    fun collect(
        submittedAtEpochMs: Long,
        deviceName: String?,
        result: String,
        verified: Boolean,
        statement: String?,
        proofBytes: ByteArray,
    ): String {
        val id = "$submittedAtEpochMs-${Random.nextInt(0x10000, 0x100000).toString(16)}"
        val recordDir = File(dir, id).apply { mkdirs() }
        try {
            File(recordDir, "proof.der").writeBytes(proofBytes)

            val debugStatement = statement?.let(WardenDebugAttestationStatement::deserializeCompact)
            debugStatement?.let { File(recordDir, "debug-statement.json").writeText(it.serialize()) }
            writeDerivedFiles(
                recordDir = recordDir,
                submittedAtEpochMs = submittedAtEpochMs,
                deviceName = deviceName,
                result = result,
                verified = verified,
                statement = debugStatement,
            )
            if (debugStatement != null) {
                archiveCommands.trySend(ArchiveCommand.StatementsChanged)
            }
            logger.info("Stored attestation proof; success=true; path={}", recordDir.absolutePath)
            return id
        } catch (exception: Exception) {
            logger.info(
                "Stored attestation proof; success=false; path={}; reason={}",
                recordDir.absolutePath,
                exception.message,
            )
            throw exception
        }
    }

    /** Requests one ZIP build; concurrent requests await the already-running build instead of scheduling another. */
    suspend fun debugStatementsArchive(): File {
        val result = CompletableDeferred<File>()
        archiveCommands.send(ArchiveCommand.Get(result))
        return result.await()
    }

    private suspend fun runArchiveWorker() {
        var dirty = true
        val waiters = mutableListOf<CompletableDeferred<File>>()
        try {
            while (currentCoroutineContext().isActive) {
                select<Unit> {
                    archiveCommands.onReceive { command ->
                        when (command) {
                            ArchiveCommand.StatementsChanged -> dirty = true
                            is ArchiveCommand.Get -> {
                                if (!dirty && debugStatementsArchive.isFile) {
                                    command.result.complete(debugStatementsArchive)
                                } else {
                                    waiters += command.result
                                    archiveRequests.trySend(Unit)
                                }
                            }
                        }
                    }
                    archiveRequests.onReceive {
                        runCatching { buildDebugStatementsArchive() }
                            .onSuccess { archive ->
                                dirty = false
                                waiters.forEach { it.complete(archive) }
                            }
                            .onFailure { failure -> waiters.forEach { it.completeExceptionally(failure) } }
                        waiters.clear()
                    }
                }
            }
        } finally {
            waiters.forEach { it.cancel() }
        }
    }

    private fun buildDebugStatementsArchive(): File {
        val statements = dir.listFiles { file -> file.isDirectory }
            ?.sortedBy { it.name }
            ?.mapNotNull { recordDir ->
                if (!File(recordDir, "record.json").isFile) return@mapNotNull null
                File(recordDir, "debug-statement.json").takeIf { it.isFile }
                    ?.let { recordDir.name to it }
            }
            ?: emptyList()

        val temporary = File.createTempFile("debug-statements-", ".zip", dir)
        try {
            ZipOutputStream(temporary.outputStream().buffered()).use { zip ->
                statements.forEach { (recordId, statement) ->
                    zip.putNextEntry(ZipEntry("$recordId/debug-statement.json"))
                    statement.inputStream().buffered().use { it.copyTo(zip) }
                    zip.closeEntry()
                }
            }
            Files.move(
                temporary.toPath(),
                debugStatementsArchive.toPath(),
                StandardCopyOption.REPLACE_EXISTING,
            )
            logger.info(
                "Generated debug statements archive; statements={}; path={}",
                statements.size,
                debugStatementsArchive.absolutePath,
            )
            return debugStatementsArchive
        } finally {
            temporary.delete()
        }
    }

    override fun close() {
        archiveScope.cancel()
    }

    private suspend fun replayStoredStatements() {
        dir.listFiles { file -> file.isDirectory }?.forEach { recordDir ->
            val statementFile = File(recordDir, "debug-statement.json")
            if (!statementFile.isFile) return@forEach

            val oldRecord = catchingUnwrapped {
                json.decodeFromString<CollectedRecord>(File(recordDir, "record.json").readText())
            }.getOrNull()
            val statement = WardenDebugAttestationStatement.deserialize(statementFile.readText())
            val replay = statement.replay()
            val replayResult = when (replay) {
                is KeyAttestation<*> -> replay.details
                is AttestationResult -> replay
                else -> error("Unsupported replay result ${replay::class.qualifiedName}")
            }
            val verified = replayResult is AttestationResult.Verified
            val result = if (verified) "Verified"
            else "TRUST: ${(replayResult as AttestationResult.Error).explanation}"

            writeDerivedFiles(
                recordDir = recordDir,
                submittedAtEpochMs = oldRecord?.submittedAtEpochMs
                    ?: recordDir.name.substringBefore('-').toLong(),
                deviceName = oldRecord?.deviceName,
                result = result,
                verified = verified,
                statement = statement,
            )
        }
    }

    private fun writeDerivedFiles(
        recordDir: File,
        submittedAtEpochMs: Long,
        deviceName: String?,
        result: String,
        verified: Boolean,
        statement: WardenDebugAttestationStatement?,
    ) {
        val chain: CertificateChain? =
            (statement?.keyAttestation as? AndroidKeystoreAttestation)?.certificateChain

        val chainFile = File(recordDir, "chain.der")
        val hasChain = chain != null && catchingUnwrapped {
            val der =
                ByteArrayOutputStream().use { out -> chain.forEach { out.write(it.encodeToDer()) }; out.toByteArray() }
            chainFile.writeBytes(der)
        }.isSuccess
        if (!hasChain) chainFile.delete()

        val attestationJson = catchingUnwrapped { chain?.androidAttestationJson() }.getOrNull()
        val attestationFile = File(recordDir, "attestation.json")
        val hasAttestationJson = attestationJson != null && catchingUnwrapped {
            attestationFile.writeText(
                prettyJson.encodeToString(
                    JsonElement.serializer(),
                    attestationJson
                )
            )
        }.isSuccess
        if (!hasAttestationJson) attestationFile.delete()

        val extension = catchingUnwrapped { chain?.androidAttestationExtension }.getOrNull()
        val hw = extension?.hardwareEnforced
        val sw = extension?.softwareEnforced

        val record = CollectedRecord(
            submittedAtEpochMs = submittedAtEpochMs,
            deviceName = deviceName,
            result = result,
            verified = verified,
            securityLevel = extract { extension?.attestationSecurityLevel?.display() },
            osAndPatch = extract {
                val version = (hw?.osVersion?.getOrNull()
                    ?: sw?.osVersion?.getOrNull())?.let { "${it.major}.${it.minor}.${it.sub}" }
                val patch = hw?.osPatchLevelLenient?.toString() ?: sw?.osPatchLevelLenient?.toString()
                listOfNotNull(version, patch).joinToString(" / ")
            },
            avb = extract { (hw?.rootOfTrust?.getOrNull() ?: sw?.rootOfTrust?.getOrNull())?.let { avbStatus(it) } },
            packageName = extract { sw?.attestationApplicationId?.getOrNull()?.packageInfos?.firstOrNull()?.packageName },
            packageVersion = extract { sw?.attestationApplicationId?.getOrNull()?.packageInfos?.firstOrNull()?.version?.toString() },
            certValidityStart = extract { chain?.leaf?.tbsCertificate?.let { "${it.validFrom.instant}" } } ?: NA,
            certValidityEnd = extract { chain?.leaf?.tbsCertificate?.let { "${it.validUntil.instant}" } } ?: NA,
            provisioning = extract {
                if (extension?.keyMintSecurityLevel != AttestationKeyDescription.SecurityLevel.SOFTWARE) chain?.let {
                    provisioning(
                        it
                    )
                } else "SOFTWARE"
            },
            createdOnDevice = extract { sw?.creationDateTime?.getOrNull()?.timestamp?.toString() },
            attestationJson = attestationJson,
            hasChain = hasChain,
            hasStatement = statement != null,
            hasAttestationJson = hasAttestationJson,
        )
        File(recordDir, "record.json").writeText(json.encodeToString(record))
    }

    fun list(): List<Pair<String, CollectedRecord>> =
        dir.listFiles { f -> f.isDirectory }
            ?.mapNotNull { d ->
                catchingUnwrapped {
                    d.name to json.decodeFromString<CollectedRecord>(
                        File(
                            d,
                            "record.json"
                        ).readText()
                    )
                }.getOrNull()
            }
            ?.sortedByDescending { it.second.submittedAtEpochMs }
            ?: emptyList()
}

// --- extraction helpers ------------------------------------------------------------------------

/** Runs an extraction step defensively; blank/failed → null (rendered as "—"). */
private inline fun extract(block: () -> String?): String? =
    catchingUnwrapped { block() }.getOrNull()?.takeUnless { it.isBlank() }

private fun AttestationKeyDescription.SecurityLevel.display(): String = when (this) {
    AttestationKeyDescription.SecurityLevel.SOFTWARE -> "Software"
    AttestationKeyDescription.SecurityLevel.TRUSTED_ENVIRONMENT -> "TEE"
    AttestationKeyDescription.SecurityLevel.STRONGBOX -> "StrongBox"
}

private fun avbStatus(rootOfTrust: AuthorizationList.RootOfTrust): String = when (rootOfTrust.verifiedBootState) {
    AuthorizationList.RootOfTrust.VerifiedBootState.Verified -> "locked"
    AuthorizationList.RootOfTrust.VerifiedBootState.SelfSigned -> "self-signed"
    else -> "unlocked"
}

private fun provisioning(chain: CertificateChain): String {
    val factory = CertificateFactory.getInstance("X.509")
    val jca = chain.map { factory.generateCertificate(ByteArrayInputStream(it.encodeToDer())) as X509Certificate }
    return if (jca.isRemoteKeyProvisioned()) "RKP" else "factory-provisioned"
}

// --- report rendering (kotlinx.html DSL — type-safe, auto-escaping) -----------------------------

private const val NA = "—"

private val columns = listOf(
    "Device", "Security", "Result", "OS / patch", "Bootloader", "Package",
    "Cert validity", "Provisioning", "Created (device)", "Submitted (server)",
    "Chain", "Proof", "Debug Statement", "Attestation",
)

fun HTML.renderCollectedReport(records: List<Pair<String, CollectedRecord>>) {
    attributes["lang"] = "en"
    head {
        meta(charset = "utf-8")
        meta(name = "viewport", content = "width=device-width, initial-scale=1")
        title { +"Warden Supreme — Collected Attestations" }
        link {
            rel = "stylesheet"
            href = "/collector.css"
            type = "text/css"
        }
        link {
            rel = "icon"
            href = "/favicon.png"
            type = "image/png"
            sizes = "any"
        }
    }
    body {
        canvas { id = "sky" }
        header {
            div("header-main") {
                h1 {
                    img(
                        alt = "Warden Supreme",
                        src = "/logo.png"
                    )
                    span {
                        +"Collected Attestations"
                    }
                }
                div("count") { +"${records.size} collected" }

                span {
                    a {
                        href = "https://a-sit-plus.github.io/warden-supreme/"
                        target = "_blank"
                        +"Learn more"
                    }
                }
                if (records.any { it.second.hasStatement }) {
                    span {
                        classes += "download"
                        a {
                            href = DEBUG_STATEMENTS_ARCHIVE_PATH
                            +"⬇ Download all debug statements ⬇"
                        }
                    }
                }
            }
            a(classes = "qr") {
                href = DemoAttestation.DOWNLOAD_PATH
                target = "_blank"
                img(
                    alt = "QR code to download the Collector APK",
                    src = "/collector-apk-qr.svg"
                )
                span { +"Click or Scan to download APK" }
            }
        }



        if (records.isEmpty()) {
            p("empty") { +"No attestations collected yet." }
        } else div("scroll") {
            table {
                thead { tr { columns.forEach { th { +it } } } }
                tbody { records.forEach { (id, record) -> reportRow(id, record) } }
            }
        }
        footer {
            +"Copyright © 2026 A-SIT Plus · "
            a {
                href = "https://plus.a-sit.at/imprint.html"
                target = "_blank"
                +"Imprint"
            }
        }
        script { unsafe { +starfieldJs } }
    }
}

/**
 * Draws a static starfield once onto `#sky` (repainted only on resize), matching the app's night sky:
 * cyan-white dots with brightness-varied radius/opacity. No animation — it is just a backdrop.
 */
private val starfieldJs = """
  (function () {
    var c = document.getElementById('sky'), x = c.getContext('2d'), stars = [];
    function build() {
      var w = c.width = window.innerWidth, h = c.height = window.innerHeight;
      var n = Math.round(w * h / 5000);
      stars = [];
      for (var i = 0; i < n; i++) {
        var b = Math.random();
        stars.push({ x: Math.random() * w, y: Math.random() * h, r: 0.3 + 0.6 * b, a: 0.2 + 0.7 * b });
      }
      draw();
    }
    function draw() {
      x.clearRect(0, 0, c.width, c.height);
      for (var i = 0; i < stars.length; i++) {
        var s = stars[i];
        x.beginPath();
        x.fillStyle = 'rgba(223,246,255,' + s.a.toFixed(3) + ')';
        x.arc(s.x, s.y, s.r, 0, 6.2832);
        x.fill();
      }
    }
    window.addEventListener('resize', build);
    build();
  })();
""".trimIndent()

private fun TBODY.reportRow(id: String, r: CollectedRecord) = tr {
    td { +(r.deviceName ?: NA) }
    td { +(r.securityLevel ?: NA) }
    td(classes = "result " + if (r.verified) "ok" else "bad") {
        div("rw") {
            attributes["title"] = r.result; +r.result
        }
    }
    td { +(r.osAndPatch ?: NA) }
    td { +(r.avb ?: NA) }
    td { +((r.packageName ?: NA) + ", v" + (r.packageVersion ?: NA)) }
    td("mono") { +(r.certValidityStart); br {}; +(r.certValidityEnd) }
    td { +(r.provisioning ?: NA) }
    td("mono") { +(r.createdOnDevice ?: NA) }
    td("mono") { +Instant.fromEpochMilliseconds(r.submittedAtEpochMs).toString() }
    td { if (r.hasChain) a("/files/$id/chain.der") { +"chain.der" } else +NA }
    td { a("/files/$id/proof.der") { +"proof.der" } }
    td { if (r.hasStatement) a("/files/$id/debug-statement.json") { +"debug-statement.json" } else +NA }
    td("att") {
        val attestation = r.attestationJson
        if (attestation == null) +NA
        else details("tree") {
            summary { +"view" }
            if (r.hasAttestationJson) span("jsonlink") { a("/files/$id/attestation.json") { +"download json" } }
            jsonTree(attestation, rootOpen = true)
        }
    }
}

/** Renders a [JsonElement] as a collapsible tree (objects/arrays as <details>, collapsed by default). */
private fun FlowContent.jsonTree(element: JsonElement, name: String? = null, rootOpen: Boolean = false) {
    when (element) {
        is JsonObject -> jsonContainer(name, element.entries.map { it.key to it.value }, "{", "}", rootOpen)
        is JsonArray -> jsonContainer(name, element.map { null to it }, "[", "]", rootOpen)
        is JsonNull -> jsonLeaf(name, "null", "z")
        is JsonPrimitive ->
            if (element.isString) jsonLeaf(name, "\"${element.content}\"", "s") else jsonLeaf(
                name,
                element.content,
                "n"
            )
    }
}

private fun FlowContent.jsonContainer(
    name: String?,
    children: List<Pair<String?, JsonElement>>,
    open: String,
    close: String,
    rootOpen: Boolean,
) = details {
    if (rootOpen) attributes["open"] = "true"
    summary {
        if (name != null) span("k") { +"\"$name\": " }
        +"$open … $close  (${children.size})"
    }
    div("ch") { children.forEach { (childName, child) -> jsonTree(child, childName) } }
}

private fun FlowContent.jsonLeaf(name: String?, value: String, cls: String) = div("leaf") {
    if (name != null) span("k") { +"\"$name\": " }
    span(cls) { +value }
}
