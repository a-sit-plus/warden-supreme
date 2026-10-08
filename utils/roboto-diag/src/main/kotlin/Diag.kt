package at.asitplus.attestation.android

import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.decodeFromPem
import at.asitplus.signum.indispensable.installIndispensable
import kotlin.io.encoding.Base64
import kotlinx.serialization.decodeFromByteArray
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security
import kotlin.system.exitProcess

fun main(args: Array<String>) {
    Signum.installIndispensable()
    Security.addProvider(BouncyCastleProvider())
    if (args.isEmpty()) {
        System.err.println("Certificate neither specified in a file (-f <path to PEM/Base64 cert>) nor as parameter <Base64 cert>!")
        exitProcess(1)
    }
    val certB64 = if (args[0] == "-f") java.io.File(args[1]).readText() else args[0]

    val certificate = if (certB64.trimStart().startsWith("-----BEGIN")) {
        Signum.Der.decodeFromPem<Certificate>(certB64)
    } else {
        Signum.Der.decodeFromByteArray<Certificate>(Base64.Mime.decode(certB64))
    }
    println(certificate.androidAttestationExtension?.prettyPrint())
}
