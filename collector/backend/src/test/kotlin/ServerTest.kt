package at.asitplus.warden

import io.ktor.client.request.get
import io.ktor.client.call.body
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.config.MapApplicationConfig
import io.ktor.server.testing.testApplication
import at.asitplus.warden.collector.shared.DemoAttestation
import io.ktor.client.statement.bodyAsText
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlin.test.*
import kotlin.io.path.createTempDirectory
import java.util.zip.ZipInputStream

class ServerTest {

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
