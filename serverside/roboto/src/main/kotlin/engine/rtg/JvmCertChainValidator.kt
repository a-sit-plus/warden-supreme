package at.asitplus.attestation.android.engine

import at.asitplus.attestation.android.*
import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.attestation.android.exceptions.CertificateInvalidException
import at.asitplus.attestation.android.exceptions.RevocationException
import at.asitplus.catchingUnwrapped
import com.android.keyattestation.verifier.SecurityLevel
import com.android.keyattestation.verifier.provider.KeyAttestationCertPath
import com.android.keyattestation.verifier.provider.KeyAttestationProvider
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.security.Security
import java.security.cert.*
import java.util.*
import kotlin.time.ExperimentalTime
import kotlin.time.toKotlinInstant

class JvmCertChainValidator(private val attestationConfiguration: AndroidAttestationConfiguration) :
    CertChainValidator<X509Certificate, KeyAttestationCertPath> {

    companion object {
        init {
            Security.addProvider(KeyAttestationProvider())
        }

        private fun getValidator() = CertPathValidator.getInstance("KeyAttestation")

    }

    private val newPkixCertPathValidator = getValidator()
    override val revocationCheckers: List<Pair<AndroidRevocationList.Loader.Configuration<*>, AndroidRevocationList.Loader>> by lazy {
        attestationConfiguration.revocation.map { (it to it.createLoader()) }
    }


    private val revocationMutex = Mutex()
    private var revocationListsFromLastCall = listOf<ConfigWithList>()
    override suspend fun revocationListsFromLastCall() = revocationMutex.withLock { revocationListsFromLastCall }


    @Throws(CertificateInvalidException::class, RevocationException::class)
    override suspend fun List<X509Certificate>.verifyCertificateChain(
        verificationDate: Date,
        actualTrustAnchors: Collection<TrustedRoot>,
        requireRKP: Boolean
    ): KeyAttestationCertPath {

        val verifyTimelyValidity =
            isRemoteKeyProvisioned() || attestationConfiguration.enforceFactoryProvisionedChainValidity

        val trustedRoot =
            catchingUnwrapped { verifyRootCertificate(verificationDate, actualTrustAnchors, verifyTimelyValidity) }
                .getOrElse {
                    throw if (it is CertificateInvalidException) it else CertificateInvalidException.InvalidRoot(
                        message = "could not verify root certificate (valid from: ${last().notBefore} to ${last().notAfter}), verification date: $verificationDate",
                        cause = it,
                        reason = if ((it is CertificateExpiredException) || (it is CertificateNotYetValidException)) CertificateInvalidException.Reason.TIME else CertificateInvalidException.Reason.TRUST,
                        certificateChain = this,
                        invalidCertificate = last()
                    )
                }
        val certificateChain =
            if (attestationConfiguration.ignoreLeafValidity) mapIndexed { i, cert ->
                if (i == 0) EternalX509Certificate(cert) else cert
            } else this



        certificateChain.reversed().zipWithNext { parent, certificate ->
            verifyCertificatePair(
                certificate,
                parent,
                verificationDate,
                verifyTimelyValidity,
                fullChainForDebugging = certificateChain
            )
        }

        //now we double-check against the new validator to rule out manipulations of the certificate chain
        catchingUnwrapped {
            newPkixCertPathValidator.validate(
                KeyAttestationCertPath(certificateChain),
                PKIXParameters(setOf(trustedRoot.trustAnchor)).apply {
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
                certificateChain = certificateChain,
                invalidCertificate = null
            )
        }

        //add it at the bottom, when we know we can trust the chain.
        //also: adding it here, makes sure it never interferes with other checks, so behavior stays the same
        if (requireRKP) {
            if (!certificateChain.isRemoteKeyProvisioned()) throw AttestationValueException(
                "Certificate chain does not contain a remotely-provisioned attestation certificate",
                reason = AttestationValueException.Reason.SEC_LEVEL, expectedValue = true, actualValue = false
            )
        }

        return KeyAttestationCertPath(this)
    }

    @OptIn(ExperimentalTime::class)
    @Throws(RevocationException::class, CertificateInvalidException::class)
    private suspend fun verifyCertificatePair(
        certificate: X509Certificate,
        parent: X509Certificate,
        verificationDate: Date,
        verifyTimelyValidity: Boolean,
        fullChainForDebugging: List<X509Certificate>
    ) {
        catchingUnwrapped {
            if (verifyTimelyValidity) certificate.checkValidity(verificationDate)
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
        if (revocationCheckers.isNotEmpty()) revocationMutex.withLock {
            catchingUnwrapped {
                revocationCheckers.map { (cfg, loader) ->
                    ConfigWithList(
                        cfg,
                        loader.load(verificationDate.toInstant().toKotlinInstant())
                    )
                }
            }.onSuccess { revocationLists ->
                revocationListsFromLastCall = revocationLists
                revocationLists.forEach {
                    it.list.find(certificate.serialNumber)?.let { entry ->
                        throw RevocationException.Revoked(
                            "Certificate ${certificate.serialNumber} revoked",
                            certificateChain = fullChainForDebugging,
                            revokedCertificate = certificate,
                            entry = entry
                        )
                    }
                }

            }.onFailure {
                throw RevocationException.ListUnavailable(
                    "Could not init revocation list",
                    it
                )
            }
        }
    }


    private fun List<X509Certificate>.verifyRootCertificate(
        verificationDate: Date,
        actualTrustAnchors: Collection<TrustedRoot>,
        verifyTimelyValidity: Boolean
    ): TrustedRoot {
        val root = last()
        if (verifyTimelyValidity) root.checkValidity(verificationDate)
        val matchingTrustAnchor = actualTrustAnchors.filter { it is TrustedRoot.Certificate }
            .firstOrNull { root.encoded.contentEquals(it.derEncoded) }
            ?: actualTrustAnchors.filter { it is TrustedRoot.PublicKey }
                .firstOrNull { root.publicKey.encoded.contentEquals(it.derEncoded) }
            ?: run {
                throw if (GOOGLE_DEFAULT_HARDWARE_TRUST_ANCHORS.map { it.publicKey.encoded }
                        .firstOrNull { it.contentEquals(root.publicKey.encoded) } != null)
                    CertificateInvalidException.OtherMatchingRoot(
                        message = "No matching root certificate. Found a default HARDWARE Root",
                        invalidCertificate = root,
                        certificateChain = this,
                        rootCertStage = CertificateInvalidException.OtherMatchingRoot.Stage.HARDWARE
                    )
                else if (GOOGLE_SOFTWARE_TRUST_ANCHORS_UNTIL_A12.map { it.publicKey.encoded }
                        .firstOrNull { it.contentEquals(root.publicKey.encoded) } != null)
                    CertificateInvalidException.OtherMatchingRoot(
                        message = "No matching root certificate. Found a default SOFTWARE (pre-Android-13) Root",
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
        root.verify(matchingTrustAnchor.publicKey)
        return matchingTrustAnchor.let {
            if (it is TrustedRoot.PublicKey && it.caName == null) it.copy(caName = root.issuerX500Principal)
            else it
        }
    }

    override val KeyAttestationCertPath.generalizedSecurityLevel: GeneralizedSecurityLevel
        get() = securityLevel().toGeneralizedSecurityLevel()
}

fun SecurityLevel?.toGeneralizedSecurityLevel(): GeneralizedSecurityLevel = when (this) {
    null, SecurityLevel.SOFTWARE -> GeneralizedSecurityLevel.SOFTWARE
    SecurityLevel.TRUSTED_ENVIRONMENT -> GeneralizedSecurityLevel.TEE
    SecurityLevel.STRONG_BOX -> GeneralizedSecurityLevel.STRONGBOX
}