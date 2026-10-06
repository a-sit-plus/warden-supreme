package at.asitplus.warden

import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.Makoto
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
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json
import java.io.File
import kotlin.test.*
import kotlin.io.path.createTempDirectory
import java.util.zip.ZipInputStream
import java.util.concurrent.atomic.AtomicInteger

class ServerTest {

    @Test
    fun `successful collection updates debug index without restart`() {
        val outputDir = createTempDirectory("collector-index-test").toFile()
        try {
            val configuration = AndroidAttestationConfiguration(
                AndroidAttestationConfiguration.AppData("test", setOf(ByteArray(32))),
                revocation = emptyList(),
            )
            val statement = Makoto(androidAttestationConfiguration = configuration)
                .collectDebugInfo(emptyList<ByteArray>(), byteArrayOf(1))
            CollectorStore(outputDir).use { store ->
                assertTrue(store.debugStatements().none())
                val id = store.collect(1500, null, "test", false, statement.serializeCompact(), byteArrayOf(1))
                store.collect(1600, null, "test", false, null, byteArrayOf(1))
                assertEquals(listOf(id), store.debugStatements(1000, 2000).map { it.parentFile.name }.toList())
                assertEquals(statement.serialize(), store.debugStatements().single().readText())
                assertFails { store.collect(1700, null, "test", false, "invalid", byteArrayOf(1)) }
                assertEquals(1, store.debugStatements().count())
            }
        } finally {
            outputDir.deleteRecursively()
        }
    }

    @Test
    fun `debug exports reject overload and release permits`() {
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
                        assertEquals(HttpStatusCode.TooManyRequests, client.get("/api/debug-statements").status)
                    } finally {
                        release.complete(Unit)
                    }
                    exports.awaitAll().forEach { assertEquals("[]", it.bodyAsText()) }
                }
                assertEquals(HttpStatusCode.OK, client.get("/api/debug-statements").status)
            }
        } finally {
            outputDir.deleteRecursively()
        }
    }

    @Test
    fun `debug statement API filters directory timestamps and validates bounds`() {
        val outputDir = createTempDirectory("collector-api-test").toFile()
        try {
            // Valid JSON payloads suffice: this endpoint must not deserialize WARDEN statements.
            val ids = listOf("2000-aaaaa", "1000-bbbbb", "999-ccccc", "1999-ddddd", "1000-aaaaa")
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

            // Rebuild solely from filesystem names, including records sharing a millisecond.
            repeat(2) {
                CollectorStore(outputDir).use { store ->
                    assertEquals(ids.sortedWith(compareBy<String> { it.substringBeforeLast('-').toLong() }.thenBy { it }),
                        store.debugStatements().map { it.parentFile.name }.toList())
                    assertEquals(listOf("1000-aaaaa", "1000-bbbbb", "1999-ddddd"),
                        store.debugStatements(1000, 2000).map { it.parentFile.name }.toList())
                    assertTrue(store.debugStatements(1000, 1000).none())
                }
            }
            testApplication {
                environment { config = MapApplicationConfig("collector.outputDir" to outputDir.absolutePath) }
                application { configureSerialization(); configureRouting() }
                suspend fun check(query: String, expected: List<String>) {
                    val response = client.get("/api/debug-statements$query")
                    assertEquals(HttpStatusCode.OK, response.status)
                    assertEquals(expected, Json.decodeFromString<List<String>>(response.bodyAsText()))
                }
                check("", listOf("999-ccccc", "1000-aaaaa", "1000-bbbbb", "1999-ddddd", "2000-aaaaa"))
                check("?from=1&to=2", listOf("1000-aaaaa", "1000-bbbbb", "1999-ddddd"))
                check("?to=1", listOf("999-ccccc"))
                check("?from=2", listOf("2000-aaaaa"))
                check("?from=1&to=1", emptyList())
                check("?from=3", emptyList())
                listOf("?from=2&to=1", "?from=no", "?to=", "?from=1.5", "?from=1&from=2",
                    "?to=${Long.MAX_VALUE}", "?from=${Long.MIN_VALUE}").forEach { query ->
                    assertEquals(HttpStatusCode.BadRequest, client.get("/api/debug-statements$query").status)
                }
                // Validation errors must not consume export permits.
                check("?from=2", listOf("2000-aaaaa"))
            }
        } finally {
            outputDir.deleteRecursively()
        }
    }

    @Test
    fun `collector policies change only their documented checks`() {
        val base = SupremeConfiguration(
            AndroidAttestationConfiguration(
                AndroidAttestationConfiguration.AppData("test", setOf(ByteArray(32))),
            )
        )

        val default = base.forCollectorPolicy(CollectorPolicy.DEFAULT).android!!
        assertTrue(default.enforceFactoryProvisionedChainValidity)
        assertFalse(default.allowBootloaderUnlock)

        val oldCertificates = base.forCollectorPolicy(CollectorPolicy.OLD_FACTORY_CERTIFICATES).android!!
        assertFalse(oldCertificates.enforceFactoryProvisionedChainValidity)
        assertFalse(oldCertificates.allowBootloaderUnlock)

        val unlocked = base.forCollectorPolicy(CollectorPolicy.UNLOCKED_BOOTLOADER).android!!
        assertFalse(unlocked.enforceFactoryProvisionedChainValidity)
        assertTrue(unlocked.allowBootloaderUnlock)

        val grapheneOs = base.forCollectorPolicy(CollectorPolicy.GRAPHENE_OS).android!!
        assertFalse(grapheneOs.enforceFactoryProvisionedChainValidity)
        assertFalse(grapheneOs.allowBootloaderUnlock)
        assertTrue(VerifiedBootKey.OEM in grapheneOs.verifiedBootKeys)
        assertTrue(grapheneOs.verifiedBootKeys.any { it is VerifiedBootKey.Digest })

        val strongBox = base.forCollectorPolicy(CollectorPolicy.STRONGBOX_ONLY).android!!
        assertTrue(strongBox.requireStrongBox)
        assertTrue(strongBox.enforceFactoryProvisionedChainValidity)
        assertFalse(strongBox.allowBootloaderUnlock)
    }

    @Test
    fun `replay failure keeps stored state`() {
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
                assertEquals("original", store.list().single().second.result)
            }

            oldFiles.forEach { (name, contents) ->
                assertContentEquals(contents, File(recordDir, name).readBytes())
            }
        } finally {
            outputDir.deleteRecursively()
        }
    }

    @Test
    fun `test root endpoint`() {
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
                assertEquals(HttpStatusCode.OK, client.get("/").status)
                assertEquals(HttpStatusCode.OK, client.get("/health").status)
                assertEquals(HttpStatusCode.OK, client.get("/collector.css").status)
                CollectorPolicy.entries.forEach { policy ->
                    val challenge = Json.decodeFromString<AttestationChallenge>(
                        client.get(policy.challengePath).bodyAsText()
                    )
                    assertTrue(challenge.attestationEndpoint.endsWith(policy.attestPath))
                }
                assertEquals(DemoAttestation.CHALLENGE_PATH, CollectorPolicy.DEFAULT.challengePath)
                assertEquals(DemoAttestation.ATTEST_PATH, CollectorPolicy.DEFAULT.attestPath)
                val version = client.get(DemoAttestation.VERSION_PATH).bodyAsText()
                assertTrue(version.toLong() > 0)
                assertEquals(HttpStatusCode.OK, client.get(DemoAttestation.DOWNLOAD_PATH).status)
                val archives = coroutineScope {
                    List(8) { async { client.get(DEBUG_STATEMENTS_ARCHIVE_PATH) } }.awaitAll()
                }
                archives.forEach { assertEquals(HttpStatusCode.OK, it.status) }
                val archiveBytes = archives.map { it.body<ByteArray>() }
                archiveBytes.drop(1).forEach { assertContentEquals(archiveBytes.first(), it) }
                ZipInputStream(archiveBytes.first().inputStream()).use {
                    assertNull(it.nextEntry)
                }
            }
        } finally {
            outputDir.deleteRecursively()
        }
    }

}
