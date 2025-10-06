package at.asitplus.attestation

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.File
import java.security.Security
import kotlin.system.exitProcess

fun main(args: Array<String>) {
    if (args.isEmpty()) {
        System.err.println("Specify a single argument pointing to a file containing one WardenDebugAttestationStatement.serializeCompact() result per line.")
        exitProcess(1)
    }
    Security.addProvider(BouncyCastleProvider())

    File(args.first()).forEachLine { line ->
        val stmt = WardenDebugAttestationStatement.deserializeCompact(line)
        println(stmt.serialize())
        //TODO Add a breakpoint to Line 19
        stmt.replaySmart(ignoreProxy = true)
    }
}
