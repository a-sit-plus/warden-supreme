package at.asitplus.attestation.supreme

import at.asitplus.KmmResult
import at.asitplus.attestation.AttestationException
import at.asitplus.attestation.Warden
import at.asitplus.catching
import at.asitplus.signum.indispensable.AndroidKeystoreAttestation
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.getJCASignatureInstance
import at.asitplus.signum.indispensable.jcaSignatureBytes
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequest
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.toJcaCertificate
import at.asitplus.attestation.supreme.AttestationResponse.Failure
import at.asitplus.signum.indispensable.pki.attestation.androidAttestationExtension
import at.asitplus.signum.indispensable.pki.leaf

import com.google.android.attestation.ParsedAttestationRecord
import kotlinx.datetime.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

/**
 * Verifies attestation statements and issues certificates on success.
 * Expects a preconfigured [Warden] instance and an OID to be used in a CSR to convey an attestation statement.
 */
class AttestationValidator(
    private val warden: Warden,
    val attestationProofOID: ObjectIdentifier,
    private val nonceValidator: NonceValidator
) {

    /**
     * Issues a new attestation challenge, using [nonce], valid for a duration of [validity], expecting an CSR containing an attestation statement to be `HTTP POST`ed to [postEndpoint]
     */
    fun issueChallenge(
        nonce: ByteArray,
        validity: Duration,
        postEndpoint: String,
        timeOffset: Duration = 5.minutes
    ) =
        AttestationChallenge(issuedAt = Clock.System.now() +timeOffset, validity, nonce, postEndpoint, attestationProofOID)

    /**
     * verifies the received CSR:
     * * Validates nonce contained in the [csr] against the [nonceValidator]
     * * extracts the attestation statement from the [csr]
     * * calls upon [warden] for key attestation based on the extracted attestation statement
     * * verifies the [csr] signature against the contained public key
     *
     * Iff all verifications succeed, [certificateIssuer] is invoked and the resulting certificate chain
     * is returned as an [AttestationResponse.Success].
     *
     * Should any verification step fail, an [AttestationResponse.Failure] is returned.
     */
    @OptIn(ExperimentalStdlibApi::class)
    suspend fun verifyKeyAttestation(
        csr: Pkcs10CertificationRequest,
        certificateIssuer: CertificateIssuer
    ): AttestationResponse {
        val nonce = csr.tbsCsr.nonce.getOrElse { return Failure(Failure.Type.CONTENT, it.message) }

        if (!nonceValidator.invoke(nonce)) return Failure(Failure.Type.CONTENT, "Invalid nonce")

        val attestationStatement = csr.tbsCsr.attestationStatementForOid(attestationProofOID)
            .getOrElse { return Failure(Failure.Type.CONTENT, it.message)}

        if(attestationStatement is AndroidKeystoreAttestation){
            println(attestationStatement.certificateChain.leaf.androidAttestationExtension)
        }
        val result = warden.verifyKeyAttestation(attestationStatement, nonce)
        return result.fold(
            onError = {
                it.cause?.printStackTrace()
                when (it.cause)  {
                    null, is AttestationException.Content -> Failure(Failure.Type.CONTENT, it.explanation)
                    is AttestationException.Certificate.Time -> Failure(Failure.Type.TIME, it.explanation)
                    is AttestationException.Certificate.Trust -> Failure(Failure.Type.TRUST, it.explanation)
                    is AttestationException.Configuration -> Failure(Failure.Type.INTERNAL, it.explanation)
                }
            },
            onSuccess = { pubKey, details ->
                val signature = csr.signatureAlgorithm.getJCASignatureInstance().getOrElse {
                    return Failure(Failure.Type.INTERNAL, it.message)
                }

                catching {
                    signature.initVerify(pubKey)
                    if (signature.verify(csr.signature.jcaSignatureBytes))
                        return Failure(Failure.Type.TRUST, "CSR signature verification failed")
                }.onFailure { return Failure(Failure.Type.INTERNAL, it.message) }

                certificateIssuer.invoke(csr).fold(
                    onSuccess = { AttestationResponse.Success(it) },
                    onFailure = { Failure(Failure.Type.INTERNAL, it.message) }
                )
            }
        )
    }
}

/**
 * invoked from [AttestationValidator.verifyKeyAttestation]. Useful to match against in-transit attestation processes.
 * Mist probably, this will check against a nonce cache and evict any matched nonce from the cache.
 * Implementing this function in a meaningful manner is absolutely crucial, since this is the actual nonce
 * matching.
 */
typealias NonceValidator = suspend (ByteArray) -> Boolean

/**
 * Gets passed the signed CSR from the mobile client after it was thoroughly checked and verified.
 * At this point, the CSR's signature has been verified, then nonce checked, and the public key attested.
 * Hence, a certificate can be issued and the whole certificate chain (from newly issued certificate up to the CA)
 * shall be returned.
 */
typealias CertificateIssuer = suspend (Pkcs10CertificationRequest) -> KmmResult<List<X509Certificate>>