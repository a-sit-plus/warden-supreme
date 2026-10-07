package at.asitplus.warden

import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.Makoto
import at.asitplus.testballoon.matrix.*
import at.asitplus.attestation.android.VerifiedBootKey
import at.asitplus.attestation.supreme.AttestationChallenge
import at.asitplus.attestation.supreme.SupremeConfiguration
import io.ktor.client.request.get
import io.ktor.client.call.body
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.application.install
import io.ktor.http.content.OutgoingContent
import io.ktor.server.config.MapApplicationConfig
import io.ktor.server.testing.testApplication
import at.asitplus.warden.collector.shared.DemoAttestation
import at.asitplus.warden.collector.shared.CollectorPolicy
import io.ktor.client.statement.bodyAsText
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json
import java.io.File
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.assertions.throwables.shouldThrowAny
import kotlin.io.path.createTempDirectory
import java.util.zip.ZipInputStream
import java.util.concurrent.atomic.AtomicInteger

val ServerTest by matrixSuite {

    "report is published on startup and collection and served from disk" {
        val outputDir = createTempDirectory("collector-report-test").toFile()
        val index = File(outputDir, "index.html")
        try {
            index.writeText("stale report")
            CollectorStore(outputDir).use { store ->
                index.readText() shouldContain "0 collected"
                coroutineScope {
                    List(8) { number ->
                        async(Dispatchers.IO) {
                            store.collect(number.toLong(), "device-$number", "test", false, null, byteArrayOf(1))
                        }
                    }.awaitAll()
                }
                val report = index.readText()
                report shouldContain "8 collected"
                repeat(8) { report shouldContain "device-$it" }
                shouldThrowAny { store.collect(100, null, "test", false, "invalid", byteArrayOf(1)) }
                index.readText() shouldBe report
                outputDir.listFiles()!!.none { it.name.startsWith("index-") } shouldBe true
            }

            index.writeText("stale report")
            testApplication {
                environment { config = MapApplicationConfig("collector.outputDir" to outputDir.absolutePath) }
                application { configureSerialization(); configureRouting() }
                startApplication()
                index.readText() shouldContain "8 collected"
                client.get("/").bodyAsText() shouldBe index.readText()
                index.writeText("served from disk")
                client.get("/").bodyAsText() shouldBe "served from disk"
            }
        } finally {
            outputDir.deleteRecursively()
        }
    }

    "successful collection updates debug index without restart" {
        val outputDir = createTempDirectory("collector-index-test").toFile()
        try {
            val configuration = AndroidAttestationConfiguration(
                AndroidAttestationConfiguration.AppData("test", setOf(ByteArray(32))),
                revocation = emptyList(),
            )
            val statement = Makoto(androidAttestationConfiguration = configuration)
                .collectDebugInfo(emptyList<ByteArray>(), byteArrayOf(1))
            CollectorStore(outputDir).use { store ->
                store.debugStatements().none() shouldBe true
                val id = store.collect(1500, null, "test", false, statement.serializeCompact(), byteArrayOf(1))
                store.collect(1600, null, "test", false, null, byteArrayOf(1))
                store.debugStatements(1000, 2000).map { it.parentFile.name }.toList() shouldBe listOf(id)
                store.debugStatements().single().readText() shouldBe statement.serialize()
                shouldThrowAny { store.collect(1700, null, "test", false, "invalid", byteArrayOf(1)) }
                store.debugStatements().count() shouldBe 1
            }
        } finally {
            outputDir.deleteRecursively()
        }
    }

    "debug exports reject overload and release permits" {
        val outputDir = createTempDirectory("collector-overload-test").toFile()
        try {
            testApplication {
                environment { config = MapApplicationConfig("collector.outputDir" to outputDir.absolutePath) }
                val started = CompletableDeferred<Unit>()
                val release = CompletableDeferred<Unit>()
                val count = AtomicInteger()
                application {
                    install(createApplicationPlugin("HoldExports") {
                        onCallRespond { call, body ->
                            if (call.request.local.uri == "/api/debug-statements" && body is OutgoingContent.WriteChannelContent) {
                                if (count.incrementAndGet() == 2) started.complete(Unit)
                                release.await()
                            }
                        }
                    })
                    configureSerialization()
                    configureRouting()
                }
                coroutineScope {
                    val exports = List(2) { async { client.get("/api/debug-statements") } }
                    try {
                        withTimeout(10000) { started.await() }
                        client.get("/api/debug-statements").status shouldBe HttpStatusCode.TooManyRequests
                    } finally {
                        release.complete(Unit)
                    }
                    exports.awaitAll().forEach { it.bodyAsText() shouldBe "[]" }
                }
                client.get("/api/debug-statements").status shouldBe HttpStatusCode.OK
            }
        } finally {
            outputDir.deleteRecursively()
        }
    }

    "startup rebuilds the index from directory names" {
        withStoredStatements { outputDir, ids ->
            repeat(2) {
                CollectorStore(outputDir).use { store ->
                    store.debugStatements().map { it.parentFile.name }.toList() shouldBe ids.sortedWith(compareBy<String> { it.substringBeforeLast('-').toLong() }.thenBy { it })
                    store.debugStatements(1000, 2000).map { it.parentFile.name }.toList() shouldBe listOf("1000-aaaaa", "1000-bbbbb", "1999-ddddd")
                    store.debugStatements(1000, 1000).none() shouldBe true
                }
            }
        }
    }

    "debug export streams nested JSON without changing numbers or escaping" {
        withStoredStatements { outputDir, _ ->
            val payload = """{"nested":[null,true,{"text":"Grüße \"quoted\" \n ${"x".repeat(32768)}"}],"decimal":0.12345678901234567890123456789,"integer":12345678901234567890123456789}"""
            File(outputDir, "1999-ddddd/debug-statement.json").writeText(payload)
            testApplication {
                environment { config = MapApplicationConfig("collector.outputDir" to outputDir.absolutePath) }
                application { configureSerialization(); configureRouting() }
                val response = client.get("/api/debug-statements?from=1&to=2")
                response.status shouldBe HttpStatusCode.OK
                Json.parseToJsonElement(response.bodyAsText()) shouldBe Json.parseToJsonElement(
                    """["1000-aaaaa","1000-bbbbb",$payload]"""
                )
            }
        }
    }

    "debug statement API parameter combinations" - {
        data("from", boundCases, nameFn = { _, case -> case.name }) - { from ->
            data("to", boundCases, nameFn = { _, case -> case.name }) test { to ->
                withStoredStatements { outputDir, ids ->
                    testApplication {
                        environment { config = MapApplicationConfig("collector.outputDir" to outputDir.absolutePath) }
                        application { configureSerialization(); configureRouting() }
                        val response = client.get("/api/debug-statements") {
                            url {
                                from.values.forEach { parameters.append("from", it) }
                                to.values.forEach { parameters.append("to", it) }
                            }
                        }
                        val invalid = from.invalid || to.invalid ||
                            (from.milliseconds != null && to.milliseconds != null && from.milliseconds > to.milliseconds)
                        if (invalid) {
                            response.status shouldBe HttpStatusCode.BadRequest
                            // Invalid parameters must leave capacity for a subsequent export.
                            client.get("/api/debug-statements").status shouldBe HttpStatusCode.OK
                        } else {
                            response.status shouldBe HttpStatusCode.OK
                            val expected = ids.filter { id ->
                                val timestamp = id.substringBeforeLast('-').toLong()
                                (from.milliseconds == null || timestamp >= from.milliseconds) &&
                                    (to.milliseconds == null || timestamp < to.milliseconds)
                            }.sortedWith(compareBy<String> { it.substringBeforeLast('-').toLong() }.thenBy { it })
                            Json.decodeFromString<List<String>>(response.bodyAsText()) shouldBe expected
                        }
                    }
                }
            }
        }
    }

    "collector policies change only their documented checks" {
        val base = SupremeConfiguration(
            AndroidAttestationConfiguration(
                AndroidAttestationConfiguration.AppData("test", setOf(ByteArray(32))),
            )
        )

        val default = base.forCollectorPolicy(CollectorPolicy.DEFAULT).android!!
        default.enforceFactoryProvisionedChainValidity shouldBe true
        default.allowBootloaderUnlock shouldBe false

        val oldCertificates = base.forCollectorPolicy(CollectorPolicy.OLD_FACTORY_CERTIFICATES).android!!
        oldCertificates.enforceFactoryProvisionedChainValidity shouldBe false
        oldCertificates.allowBootloaderUnlock shouldBe false

        val unlocked = base.forCollectorPolicy(CollectorPolicy.UNLOCKED_BOOTLOADER).android!!
        unlocked.enforceFactoryProvisionedChainValidity shouldBe false
        unlocked.allowBootloaderUnlock shouldBe true

        val grapheneOs = base.forCollectorPolicy(CollectorPolicy.GRAPHENE_OS).android!!
        grapheneOs.enforceFactoryProvisionedChainValidity shouldBe false
        grapheneOs.allowBootloaderUnlock shouldBe false
        (VerifiedBootKey.OEM in grapheneOs.verifiedBootKeys) shouldBe true
        grapheneOs.verifiedBootKeys.any { it is VerifiedBootKey.Digest } shouldBe true

        val strongBox = base.forCollectorPolicy(CollectorPolicy.STRONGBOX_ONLY).android!!
        strongBox.requireStrongBox shouldBe true
        strongBox.enforceFactoryProvisionedChainValidity shouldBe true
        strongBox.allowBootloaderUnlock shouldBe false
    }

    "replay failure keeps stored state" {
        val outputDir = createTempDirectory("collector-replay-test").toFile()
        try {
            val recordDir = File(outputDir, "1234-dead").apply { mkdirs() }
            val oldFiles = mapOf(
                "record.json" to """{
                    "submittedAtEpochMs": 1234,
                    "result": "original",
                    "verified": false,
                    "certValidityStart": "old-start",
                    "certValidityEnd": "old-end",
                    "hasChain": true,
                    "hasStatement": true
                }""".trimIndent().encodeToByteArray(),
                "debug-statement.json" to "invalid debug statement".encodeToByteArray(),
                "proof.der" to byteArrayOf(1, 2, 3),
                "chain.der" to byteArrayOf(4, 5, 6),
            )
            oldFiles.forEach { (name, contents) -> File(recordDir, name).writeBytes(contents) }

            CollectorStore(outputDir).use { store ->
                store.list().single().second.result shouldBe "original"
            }

            oldFiles.forEach { (name, contents) ->
                File(recordDir, name).readBytes().contentEquals(contents) shouldBe true
            }
        } finally {
            outputDir.deleteRecursively()
        }
    }

    "test root endpoint" {
        val outputDir = createTempDirectory("collector-test").toFile()
        try {
            testApplication {
                environment {
                    config = MapApplicationConfig("collector.outputDir" to outputDir.absolutePath)
                }
                application {
                    configureSerialization()
                    configureRouting()
                }
                // verify server root returns 200
                client.get("/").status shouldBe HttpStatusCode.OK
                client.get("/health").status shouldBe HttpStatusCode.OK
                client.get("/collector.css").status shouldBe HttpStatusCode.OK
                CollectorPolicy.entries.forEach { policy ->
                    val challenge = Json.decodeFromString<AttestationChallenge>(
                        client.get(policy.challengePath).bodyAsText()
                    )
                    challenge.attestationEndpoint.endsWith(policy.attestPath) shouldBe true
                }
                CollectorPolicy.DEFAULT.challengePath shouldBe DemoAttestation.CHALLENGE_PATH
                CollectorPolicy.DEFAULT.attestPath shouldBe DemoAttestation.ATTEST_PATH
                val version = client.get(DemoAttestation.VERSION_PATH).bodyAsText()
                (version.toLong() > 0) shouldBe true
                client.get(DemoAttestation.DOWNLOAD_PATH).status shouldBe HttpStatusCode.OK
                val archives = coroutineScope {
                    List(8) { async { client.get(DEBUG_STATEMENTS_ARCHIVE_PATH) } }.awaitAll()
                }
                archives.forEach { it.status shouldBe HttpStatusCode.OK }
                val archiveBytes = archives.map { it.body<ByteArray>() }
                archiveBytes.drop(1).forEach { it.contentEquals(archiveBytes.first()) shouldBe true }
                ZipInputStream(archiveBytes.first().inputStream()).use {
                    it.nextEntry shouldBe null
                }
            }
        } finally {
            outputDir.deleteRecursively()
        }
    }

}

private data class BoundCase(
    val name: String,
    val values: List<String>,
    val milliseconds: Long? = null,
    val invalid: Boolean = false,
)

private val boundCases = listOf(
    BoundCase("omitted", emptyList()),
    BoundCase("negative", listOf("-1"), -1000),
    BoundCase("zero", listOf("0"), 0),
    BoundCase("first boundary", listOf("1"), 1000),
    BoundCase("last boundary", listOf("2"), 2000),
    BoundCase("after all statements", listOf("3"), 3000),
    BoundCase("lowest representable seconds", listOf("-9223372036854775"), -9223372036854775000L),
    BoundCase("highest representable seconds", listOf("9223372036854775"), 9223372036854775000L),
    BoundCase("empty", listOf(""), invalid = true),
    BoundCase("non-numeric", listOf("no"), invalid = true),
    BoundCase("fractional", listOf("1.5"), invalid = true),
    BoundCase("lower conversion overflow", listOf(Long.MIN_VALUE.toString()), invalid = true),
    BoundCase("upper conversion overflow", listOf(Long.MAX_VALUE.toString()), invalid = true),
    BoundCase("integer parsing overflow", listOf("9223372036854775808"), invalid = true),
    BoundCase("duplicate equal values", listOf("1", "1"), invalid = true),
    BoundCase("duplicate different values", listOf("1", "2"), invalid = true),
)

private suspend fun withStoredStatements(action: suspend (File, List<String>) -> Unit) {
    val outputDir = createTempDirectory("collector-api-test").toFile()
    try {
        // JSON payloads suffice: the export must not deserialize WARDEN statements.
        val ids = listOf("2000-aaaaa", "1000-bbbbb", "999-ccccc", "1999-ddddd", "1000-aaaaa", "-1-eeeee", "0-fffff")
        ids.forEach { id ->
            File(outputDir, id).mkdirs()
            File(outputDir, "$id/record.json").writeText("{}")
            File(outputDir, "$id/debug-statement.json").writeText("\"$id\"")
        }
        File(outputDir, "1500-incomplete").mkdirs()
        File(outputDir, "1500-incomplete/debug-statement.json").writeText("{}")
        File(outputDir, "not-a-record").mkdirs()
        File(outputDir, "not-a-record/record.json").writeText("{}")
        File(outputDir, "not-a-record/debug-statement.json").writeText("{}")
        File(outputDir, "1200-nostatement").mkdirs()
        File(outputDir, "1200-nostatement/record.json").writeText("{}")
        action(outputDir, ids)
    } finally {
        outputDir.deleteRecursively()
    }
}
