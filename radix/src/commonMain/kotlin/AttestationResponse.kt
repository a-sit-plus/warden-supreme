package at.asitplus.veritatis

import at.asitplus.signum.indispensable.io.X509CertificateBase64UrlSerializer
import at.asitplus.signum.indispensable.pki.X509Certificate
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
sealed class AttestationResponse {

    @SerialName("Success")
    @Serializable
    class Success(
        val certificateChain: List<@Serializable(with = X509CertificateBase64UrlSerializer::class) X509Certificate>
    ) : AttestationResponse()

    @SerialName("Failure")
    @Serializable
    class Failure(val kind: Type, val explanation: String?) : AttestationResponse() {
        @Serializable
        enum class Type {
            TRUST,
            TIME,

            /**
             * Invalid attestation proof content. I.e., a CSR without a nonce, an invalid nonce, or containing a non-parsable Attestation statement
             */
            CONTENT,
            INTERNAL
        }
    }
}