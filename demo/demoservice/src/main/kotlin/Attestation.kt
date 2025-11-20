package at.asitplus.warden

import at.asitplus.attestation.AttestationResult
import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.attestation.Makoto
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.parseHex
import at.asitplus.attestation.supreme.AttestationVerifier
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequest
import com.google.android.attestation.ParsedAttestationRecord
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.util.*
import kotlin.time.ExperimentalTime


@OptIn(ExperimentalTime::class)
fun Application.configureAttestation() {

    val ENDPOINT_CHALLENGE = "/api/v1/challenge"
    val PATH_ATTEST = "/api/v1/attest"

    val makoto = Makoto(
        androidAttestationConfiguration = AndroidAttestationConfiguration(
            AndroidAttestationConfiguration.AppData(
                packageName = "at.asitplus.warden.demoapp",
                //Fingerprint of the test signer used for this Android Build
                signerFingerprints = listOf("a3e55ba9457de2900fe86303a5d556c496b691afff2c0dd50488bed3e400cc6b".parseHex()),
            ),
            //NEVER ENABLE SOFTWARE AND HARDWARE ATTESTATION AT THE SAME TIME IN PRODUCTION
            //NEVER ON THE SAME STAGE!!!
            //STRICTLY SEPARATE MAKOTO/VERIFIER INSTANCES FOR SW AND HW ATTESTATION.
            //OTHERWISE, AN SW-ATTESTED DEVICE CAN BE MANIPULATED TO CLAIM HW ATTESTATION
            enableSoftwareAttestation = true //so we can test with the emulator
        ), iosAttestationConfiguration = IosAttestationConfiguration(
            IosAttestationConfiguration.AppData(
                teamIdentifier = "9CYHJNG644", //adapt to your team ID
                bundleIdentifier = "at.asitplus.warden.demoapp.demoapp",
                sandbox = true, //if you are using a dev build (which will be the case)
            )
        )
    )

    val verifier = AttestationVerifier(makoto)
    val html = this::class.java.classLoader.getResourceAsStream("attestation-failed.html").reader().readText()
    routing {
        get(ENDPOINT_CHALLENGE) {

            call.respond(verifier.issueChallenge("http://${call.request.host()}:8080$PATH_ATTEST"))
        }
        post(PATH_ATTEST) {
            val decodedCSR = Pkcs10CertificationRequest.decodeFromDer(call.receive<ByteArray>())
            val result = verifier.verifyAttestation(
                decodedCSR,
                onAttestationError = {
                    log.warn(explanation, cause)
                    //send a pretty explanation to the client.
                    //NOTE: you should never be this verbose in production
                    html.replaceFirst("%%%%%", explanation.escapeHTML())
                }
            ) {
                //Because this is a test setup, where we allow software and hardware, we add an extension to the certificate
                //to indicate this
                val hw = when (this) {
                    is AttestationResult.Android.Verified -> this.attestationRecord.keymasterSecurityLevel() != ParsedAttestationRecord.SecurityLevel.SOFTWARE
                    is AttestationResult.IOS.Verified -> true
                }
                SIGNER.issueCertificate(it, CA_CERT, hw)
            }
            call.respond(result)
        }
    }
}