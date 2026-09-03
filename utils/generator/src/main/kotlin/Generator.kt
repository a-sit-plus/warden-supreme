package at.asitplus.attestation.generator

import at.asitplus.signum.indispensable.asn1.encodeToPEM
import java.io.File

/**
 * CLI: `generator <config.json>`.
 *
 * Writes one certificate chain and one attested private key per [AttestationSpec], plus the root
 * certificate, into [GeneratorConfig.outputDirectory].
 */
fun main(args: Array<String>) {
    require(args.size == 1) { "Usage: generator <config.json>" }
    val config = GeneratorConfig.fromJson(File(args.single()).readText())
    val issuer = AndroidAttestationIssuer.from(config.issuer)
    val destination = File(config.outputDirectory).apply { mkdirs() }

    config.attestations.forEachIndexed { index, attestation ->
        val issued = issuer.issue(attestation)
        File(destination, "attestation-$index-chain.pem").writeText(issued.chainPem())
        File(destination, "attestation-$index-key.pem").writeText(issued.leafPrivateKeyPem())
    }
    File(destination, "root.pem").writeText(issuer.rootCertificate.encodeToPEM().getOrThrow())
}
