package at.asitplus.warden

import com.android.keyattestation.verifier.SecurityLevel
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun Application.configureRouting() {
    routing {
        get("/") {
            call.respondText("Hello World!")
        }

        authenticate("demojwt") {
            get("/protected") {
                val authenticatedSubject = call.principal<AttestationLevel>()
                val rsrc= when(authenticatedSubject) {
                    AttestationLevel.HARDWARE -> "granted.html"
                    AttestationLevel.SOFTWARE -> "protected.html"
                    null -> throw RuntimeException("Unauthorized")
                }

                val html= this@configureRouting::class.java.classLoader.getResourceAsStream(rsrc).reader().readText()
                call.respondText(html, ContentType.Text.Html)
            }
        }

    }
}
