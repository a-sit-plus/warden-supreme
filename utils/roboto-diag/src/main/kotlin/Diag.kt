package at.asitplus.attestation.android

import at.asitplus.signum.indispensable.pki.X509Certificate
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security
import kotlin.system.exitProcess

fun main(args: Array<String>) {
    Security.addProvider(BouncyCastleProvider())
    if (args.isEmpty()) {
        System.err.println("Certificate neither specified in a file (-f <path to PEM/Base64 cert>) nor as parameter <Base64 cert>!")
        exitProcess(1)
    }
    val certB64 = if (args[0] == "-f") java.io.File(args[1]).readText() else args[0]

    println(
        X509Certificate.decodeFromByteArray(certB64.encodeToByteArray())?.androidAttestationExtension?.prettyPrint()
    )
}
