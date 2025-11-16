package docs.service.callbacks

import at.asitplus.attestation.AttestationResult
import at.asitplus.attestation.supreme.PreAttestationError
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequest
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.supreme.sign.Signer
import docs.config.minimal.verifier

val PATH_CHALLENGE = "/api/v1/challenge"
val PATH_ATTEST = "/api/v1/attest"

val publicEndpoint: String = ""
val signer = Signer.Ephemeral {
    ec { }
}.getOrThrow()

var issuerName = listOf(
    RelativeDistinguishedName(
        AttributeTypeAndValue.CommonName(
            Asn1String.UTF8("Supreme Verifier")
        )
    )
)
var subjectName = listOf(
    RelativeDistinguishedName(
        AttributeTypeAndValue.CommonName(
            Asn1String.UTF8("Supreme Client")
        )
    )
)

val caCert: X509Certificate = TODO()
val csr: Pkcs10CertificationRequest = TODO()


suspend fun foo() {
    val result = verifier.verifyAttestation(
        /*(1)!*/csr = csr,
        onPreAttestationError = {
            /*(2)!*/when (this) {
            is PreAttestationError.AttestationStatementExtraction -> TODO()
            is PreAttestationError.ChallengeExtraction -> TODO()
            is PreAttestationError.ChallengeVerification -> TODO()
            is PreAttestationError.OperationalError -> TODO()
        }
            /*(3)!*/null
        },
        onAttestationError = { debugStatement ->
            val attestationException = cause
            val reason = explanation
            null
        },
        onAttestationSuccess = { attestedKey ->
            when (this) {
                is AttestationResult.Android.Verified -> TODO()
                is AttestationResult.IOS.Verified -> TODO()
            }

        }
    ) { csr, attestationResult ->
        TODO("Certificate issuing logic")
    }
}
