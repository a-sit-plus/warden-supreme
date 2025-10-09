package at.asitplus.attestation.android

import at.asitplus.attestation.android.exceptions.CertificateInvalidException
import at.asitplus.attestation.android.exceptions.RevocationException
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.Date

interface CertChainValidator {
    @Throws(CertificateInvalidException::class, RevocationException::class)
    fun verifyCertificateChain(
        certificateChain: List<X509Certificate>,
        verificationDate: Date,
        actualTrustAnchors: Collection<PublicKey>,
        ignoreLeafValidity: Boolean
    )
}