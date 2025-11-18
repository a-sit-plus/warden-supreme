package at.asitplus.warden

import io.ktor.server.application.*

fun main(args: Array<String>) {
    io.ktor.server.netty.EngineMain.main(args)
}

fun Application.module() {
    configureLogging()
    loadKeyStore()
    configureSecurity()
    configureAttestation()
    configureSerialization()
    configureRouting()
}
