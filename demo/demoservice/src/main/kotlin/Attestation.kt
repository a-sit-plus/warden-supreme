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
//TODO Attestation here
}