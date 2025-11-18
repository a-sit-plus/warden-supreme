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
import io.ktor.server.plugins.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlin.time.ExperimentalTime


@OptIn(ExperimentalTime::class)
fun Application.configureAttestation() {

    val ENDPOINT_CHALLENGE = "/api/v1/challenge"
    val PATH_ATTEST = "/api/v1/attest"
    //This is the default, wehn using an Android emulator
    val ENDPOINT_ATTEST = "http://10.0.2.2:8080$PATH_ATTEST"


    val makoto = Makoto(
        androidAttestationConfiguration = AndroidAttestationConfiguration(AndroidAttestationConfiguration.AppData(
            packageName = "at.asitplus.warden.demoapp",
            //Fingerprint of the test signer used for this Android Build
            signerFingerprints = listOf("a3e55ba9457de2900fe86303a5d556c496b691afff2c0dd50488bed3e400cc6b".parseHex()),
        ),
            enableSoftwareAttestation = true //so we can test with the emulator
        ), iosAttestationConfiguration = IosAttestationConfiguration(IosAttestationConfiguration.AppData(
            teamIdentifier = "9CYHJNG644", //adapt to your team ID
            bundleIdentifier = "at.asitplus.warden.demoapp.demoapp",
            sandbox = true, //if you are using a dev build (which will be the case)
        )
        )
    )

    val verifier = AttestationVerifier(makoto)

    routing {
        get(ENDPOINT_CHALLENGE) {

            //Android emulator says localhost as source, real device has a real IP
            val endpoint =                                                              //This happened to be the IP address
                                                                                        //of my physical device when preparing this code.
                                                                                        //You only need this for device testing
                if (call.request.origin.remoteHost == "localhost") ENDPOINT_ATTEST else "http://10.6.252.4:8080$PATH_ATTEST"
            call.respond(verifier.issueChallenge(endpoint))
        }
        post(PATH_ATTEST) {
            val decodedCSR = Pkcs10CertificationRequest.decodeFromDer(call.receive<ByteArray>())
            val result = verifier.verifyAttestation(decodedCSR) {
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