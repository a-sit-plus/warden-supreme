package at.asitplus.warden

import io.ktor.client.request.get
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.testing.testApplication
import kotlin.test.*

class ServerTest {

    @Test
    fun `test root endpoint`() = testApplication {
        application {
            configureSerialization()
            configureRouting()
        }
        // verify server root returns 200
        assertEquals(HttpStatusCode.OK, client.get("/").status)
    }

}
