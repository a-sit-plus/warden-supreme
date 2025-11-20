package at.asitplus.warden

import io.ktor.server.application.*
import java.net.NetworkInterface

fun main(args: Array<String>) {
    val addresses = NetworkInterface.getNetworkInterfaces().asSequence()
        .filter { it.isUp && !it.isLoopback }
        .flatMap { it.inetAddresses.asSequence() }
        .filter { !it.isLoopbackAddress }
        .map { it.hostAddress }
        .toList()

    println("Addresses:")
    addresses.forEach { println(it) }
    println()
    Thread.sleep(2000)

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
