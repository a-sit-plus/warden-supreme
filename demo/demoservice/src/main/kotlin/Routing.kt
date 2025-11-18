package at.asitplus.warden

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

        authenticate("jwt") {
            get("/protected") {
                val authenticatedSubject = call.principal<UserIdPrincipal>()
                val rsrc= if(authenticatedSubject?.name == "HW") "granted.html" else "protected.html"
                val html= this@configureRouting::class.java.classLoader.getResourceAsStream(rsrc).reader().readText()
               // val message =
                //    "Welcome, ${authenticatedSubject?.name}!" + "\nThis message is for your eyes only."
               // call.respondText(message, ContentType.Text.Plain.withCharset(Charsets.UTF_8))
                call.respondText(html, ContentType.Text.Html)
            }
        }

    }
}
