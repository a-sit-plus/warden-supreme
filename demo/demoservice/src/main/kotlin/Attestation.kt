package at.asitplus.warden

import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.attestation.Makoto
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.parseHex
import at.asitplus.attestation.supreme.AttestationVerifier
import at.asitplus.signum.indispensable.asn1.Asn1Time
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequest
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import at.asitplus.signum.supreme.sign
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.ExperimentalTime


@OptIn(ExperimentalTime::class)
 fun Application.configureAttestation() {


    val makoto = Makoto(
        androidAttestationConfiguration = AndroidAttestationConfiguration(/*(1)!*/AndroidAttestationConfiguration.AppData(
            packageName = "at.asitplus.attestation_client",
            signerFingerprints = listOf("34 b9 76 2c 4d 6c 90 d4 84 31 94 0c 57 bd e7 31 42 58 b2 64 20 ec".parseHex())
        )
        ), iosAttestationConfiguration = IosAttestationConfiguration(/*(2)!*/IosAttestationConfiguration.AppData(
            teamIdentifier = "9CYHJNG644",
            bundleIdentifier = "at.asitplus.attestation-client",
        )
        )
    )

    val verifier = AttestationVerifier(makoto)

    routing {
        get(ENDPOINT_CHALLENGE) {
            call.respond(verifier.issueChallenge(ENDPOINT_ATTEST))
        }
        post(PATH_ATTEST) {

            val decodedCSR = Pkcs10CertificationRequest.decodeFromDer(call.receive<ByteArray>())
            val result = verifier.verifyAttestation(decodedCSR) {

                val leafCertificate = SIGNER.sign(
                    TbsCertificate(
                        serialNumber = Random.nextBytes(32),
                        publicKey = it.tbsCsr.publicKey,
                        signatureAlgorithm = SIGNER.signatureAlgorithm.toX509SignatureAlgorithm().getOrThrow(),
                        validFrom = Asn1Time(Clock.System.now()),
                        validUntil = Asn1Time(Clock.System.now() + 10.days),
                        issuerName = CA_CERT.tbsCertificate.subjectName,
                        subjectName = subjectName,
                    )
                ).getOrThrow()
                listOf(leafCertificate, CA_CERT)
            }
            call.respond(result)
        }
    }
}