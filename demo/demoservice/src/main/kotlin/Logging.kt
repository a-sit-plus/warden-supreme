package at.asitplus.warden

import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.plugins.calllogging.CallLogging
import io.ktor.server.request.httpMethod
import io.ktor.server.request.path
import org.slf4j.event.Level

fun Application.configureLogging() {

    install(CallLogging) {
        level = Level.TRACE        // or DEBUG
        filter { _ -> true }    // log every call
        mdc("method") { it.request.httpMethod.value }
        mdc("path") { it.request.path() }
        // You can also add custom formatters, etc.
    }
}