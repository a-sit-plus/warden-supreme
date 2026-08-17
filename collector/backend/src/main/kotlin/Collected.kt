@file:OptIn(ExperimentalTime::class)

package at.asitplus.warden

import at.asitplus.attestation.WardenDebugAttestationStatement
import at.asitplus.attestation.android.*
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.AndroidKeystoreAttestation
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.leaf
import at.asitplus.warden.collector.shared.androidAttestationJson
import kotlinx.html.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import kotlin.random.Random
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

private val json = Json { ignoreUnknownKeys = true }
private val prettyJson = Json { prettyPrint = true }

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
class CollectorStore(private val dir: File) {
    init {
        dir.mkdirs()
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

        File(recordDir, "proof.der").writeBytes(proofBytes)

        var hasStatement = false
        val chain: CertificateChain? = statement?.let { compact ->
            val pretty = catchingUnwrapped {
                WardenDebugAttestationStatement.deserializeCompact(compact).serialize()
            }.getOrNull()
            File(recordDir, "debug-statement.json").writeText(pretty ?: compact)
            hasStatement = true
            catchingUnwrapped {
                (WardenDebugAttestationStatement.deserializeCompact(compact).keyAttestation as? AndroidKeystoreAttestation)
                    ?.certificateChain
            }.getOrNull()
        }

        var hasChain = false
        if (chain != null) catchingUnwrapped {
            val der =
                ByteArrayOutputStream().use { out -> chain.forEach { out.write(it.encodeToDer()) }; out.toByteArray() }
            File(recordDir, "chain.der").writeBytes(der)
            hasChain = true
        }

        val attestationJson = catchingUnwrapped { chain?.androidAttestationJson() }.getOrNull()
        var hasAttestationJson = false
        if (attestationJson != null) catchingUnwrapped {
            File(recordDir, "attestation.json").writeText(
                prettyJson.encodeToString(
                    JsonElement.serializer(),
                    attestationJson
                )
            )
            hasAttestationJson = true
        }

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
            hasStatement = hasStatement,
            hasAttestationJson = hasAttestationJson,
        )
        File(recordDir, "record.json").writeText(json.encodeToString(record))
        return id
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

private val reportCss = """
  :root { color-scheme: dark; }
  body { margin: 0; background: #0D1117; color: #F0F6FC; font-family: -apple-system, Segoe UI, Roboto, sans-serif; }
  /* Static night sky behind everything: fixed to the viewport, painted once, non-interactive. */
  #sky { position: fixed; inset: 0; width: 100%; height: 100%; z-index: -1; pointer-events: none; }
  header { padding: 20px 24px; border-bottom: 1px solid #243441; }
  h1 { margin: 0; font-size: 3.25rem; color: #01f9fe; font-weight: 600; display: flex; align-items: center; flex-wrap: wrap; gap: 0.5rem; }
  h1 > span { align-self: center; white-space: nowrap; line-height: 1; padding-left: 1rem; }
  h1 > img { display: block; }
  .count { color: #9FB2C2; font-size: .85rem; margin-top: 4px; }
  .scroll { overflow-x: auto; padding: 16px 24px 32px; }
  table { border-collapse: collapse; width: 100%; font-size: .82rem; white-space: nowrap; }
  th, td { padding: 8px 12px; border-bottom: 1px solid #1E242A; text-align: left; }
  thead th { position: sticky; top: 0; background: #11202B; color: #00C1FF; font-weight: 600; border-bottom: 1px solid #243441; }
  tbody tr:hover { background: #11181F; }
  th:not(:last-child),
  td:not(:last-child) {
      width: 1%;
      white-space: nowrap;
  }

  th:last-child,
  td:last-child {
      width: auto;
  }
  td.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .78rem; color: #C9D6E2; }
  td.ok { color: #2FB170; font-weight: 600; }
  td.bad { color: #E6695B; }
  /* Auto table-layout squeezes the only wrappable column to its longest word; a fixed-width inner
     block box the cell can't shrink below is the reliable fix. */
  td.result div.rw { width: 300px; white-space: normal; overflow-wrap: normal; word-break: normal; }
  a { color: #00C1FF; }
  .empty { padding: 24px; color: #9FB2C2; }
  td.att { vertical-align: top; max-width: 640px; }
  td.att > details.tree > summary { color: #00C1FF; cursor: pointer; }
  .tree, .tree details { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .78rem; white-space: normal; }
  .tree details > summary { cursor: pointer; color: #9FB2C2; }
  .tree .ch { margin-left: 12px; padding-left: 8px; border-left: 1px solid #1E242A; }
  .tree .leaf { padding: 1px 0; }
  .tree .k { color: #00C1FF; }
  .tree .s { color: #2FB170; }
  .tree .n { color: #E6695B; }
  .tree .z { color: #9FB2C2; }
  .jsonlink { display: block; margin-bottom: 6px; font-size: .72rem; }
  footer { padding: 16px 24px 28px; border-top: 1px solid #243441; color: #9FB2C2; font-size: .8rem; }
  footer a { color: #00C1FF; }
""".trimIndent()

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
        style { unsafe { +reportCss } }
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
                    href = "https://a-sit-plus.github.io"
                    target = "_blank"
                    +"Learn more"
                }
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
            +"© 2026 A-SIT Plus · "
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
