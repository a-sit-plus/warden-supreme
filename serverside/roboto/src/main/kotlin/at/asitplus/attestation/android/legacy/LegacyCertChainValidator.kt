package at.asitplus.attestation.android.legacy

import at.asitplus.attestation.android.*
import at.asitplus.attestation.android.exceptions.CertificateInvalidException
import at.asitplus.attestation.android.exceptions.RevocationException
import at.asitplus.catchingUnwrapped
import com.android.keyattestation.verifier.provider.KeyAttestationCertPath
import com.android.keyattestation.verifier.provider.KeyAttestationProvider
import io.ktor.client.*
import io.ktor.client.engine.cio.*
import java.security.PublicKey
import java.security.Security
import java.security.cert.*
import java.util.*


internal class LegacyCertChainValidator(httpProxy: String?) : CertChainValidator {
    companion object {
        init {
            Security.addProvider(KeyAttestationProvider())
        }

        private val newPkixCertPathValidator = CertPathValidator.getInstance("KeyAttestation")

    }

    private val revocationListClient = HttpClient(CIO) { setup(httpProxy) }


    //keep a default implementation that is sensible
    @Throws(CertificateInvalidException::class, RevocationException::class)
    override fun verifyCertificateChain(
        certificateChain: List<X509Certificate>,
        verificationDate: Date,
        actualTrustAnchors: Collection<PublicKey>,
        ignoreLeafValidity: Boolean
    ) {
        catchingUnwrapped { certificateChain.verifyRootCertificate(verificationDate, actualTrustAnchors) }
            .onFailure {
                throw if (it is CertificateInvalidException) it else CertificateInvalidException.InvalidRoot(
                    message = "could not verify root certificate (valid from: ${certificateChain.last().notBefore} to ${certificateChain.last().notAfter}), verification date: $verificationDate",
                    cause = it,
                    reason = if ((it is CertificateExpiredException) || (it is CertificateNotYetValidException)) CertificateInvalidException.Reason.TIME else CertificateInvalidException.Reason.TRUST,
                    certificateChain = certificateChain,
                    invalidCertificate = certificateChain.last()
                )
            }
        val revocationStatusList = catchingUnwrapped { RevocationList.fromGoogleServer(client = revocationListClient) }
            .getOrElse {
                throw RevocationException.ListUnavailable(
                    "could not download revocation information",
                    it
                )
            }
        val finalCertificateChain =
            if (ignoreLeafValidity) certificateChain.mapIndexed { i, cert ->
                if (i == 0) EternalX509Certificate(cert) else cert
            } else certificateChain

        finalCertificateChain.reversed().zipWithNext { parent, certificate ->
            verifyCertificatePair(certificate, parent, verificationDate, revocationStatusList, finalCertificateChain)
        }

        //now we double-check against the new validator to rule out manipulations of the certificate chain
        catchingUnwrapped {
            newPkixCertPathValidator.validate(
                KeyAttestationCertPath(finalCertificateChain),
                PKIXParameters(
                    setOf(TrustAnchor(finalCertificateChain.last(), null))
                ).apply {
                    date = verificationDate
                    isRevocationEnabled =
                        false //we check manually as per the official documentation, and we've done that already
                }
            )
        }.onFailure {
            throw CertificateInvalidException(
                message = "PKIX cert path validation failed",
                it,
                reason = CertificateInvalidException.Reason.TRUST, //we have ruled out time beforehand
                certificateChain = finalCertificateChain,
                invalidCertificate = null
            )
        }

    }

    @Throws(RevocationException::class, CertificateInvalidException::class)
    private fun verifyCertificatePair(
        certificate: X509Certificate,
        parent: X509Certificate,
        verificationDate: Date,
        statusList: RevocationList,
        fullChainForDebugging: List<X509Certificate>
    ) {
        catchingUnwrapped {
            certificate.checkValidity(verificationDate)
            certificate.verify(parent.publicKey)
        }.onFailure {
            throw CertificateInvalidException(
                message = "Certificate ${certificate.serialNumber} could not be verified",
                cause = it,
                reason = if ((it is CertificateExpiredException) || (it is CertificateNotYetValidException)) CertificateInvalidException.Reason.TIME else CertificateInvalidException.Reason.TRUST,
                certificateChain = fullChainForDebugging,
                invalidCertificate = certificate
            )
        }
        catchingUnwrapped {
            statusList.isRevoked(certificate.serialNumber)
        }.onSuccess {
            if (it)
                throw RevocationException.Revoked(
                    "Certificate ${certificate.serialNumber} revoked",
                    certificateChain = fullChainForDebugging,
                    revokedCertificate = certificate
                )
        }.onFailure {
            throw RevocationException.ListUnavailable(
                "Could not init revocation list",
                it
            )
        }
    }

    private fun List<X509Certificate>.verifyRootCertificate(
        verificationDate: Date,
        actualTrustAnchors: Collection<PublicKey>,
    ) {
        val root = last()
        root.checkValidity(verificationDate)
        val matchingTrustAnchor = actualTrustAnchors
            .firstOrNull { root.publicKey.encoded.contentEquals(it.encoded) }
            ?: run {
                throw if (DEFAULT_HARDWARE_TRUST_ANCHORS.map { it.encoded }
                        .firstOrNull { it.contentEquals(root.publicKey.encoded) } != null)
                    CertificateInvalidException.OtherMatchingRoot(
                        message = "No matching root certificate. Found a default HARDWARE Root",
                        invalidCertificate = root,
                        certificateChain = this,
                        rootCertStage = CertificateInvalidException.OtherMatchingRoot.Stage.HARDWARE
                    )
                else if (DEFAULT_SOFTWARE_TRUST_ANCHORS.map { it.encoded }
                        .firstOrNull { it.contentEquals(root.publicKey.encoded) } != null)
                    CertificateInvalidException.OtherMatchingRoot(
                        message = "No matching root certificate. Found a default SOFTWARE Root",
                        invalidCertificate = root,
                        certificateChain = this,
                        rootCertStage = CertificateInvalidException.OtherMatchingRoot.Stage.SOFTWARE
                    )
                else CertificateInvalidException.NoMatchingRoot(
                    "No matching root certificate. Found an unknown Root",
                    invalidCertificate = root,
                    certificateChain = this
                )
            }
        root.verify(matchingTrustAnchor)
    }

}
