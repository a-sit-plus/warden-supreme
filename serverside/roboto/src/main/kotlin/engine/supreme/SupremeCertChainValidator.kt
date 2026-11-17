@file:OptIn(at.asitplus.signum.indispensable.pki.ExperimentalPkiApi::class)

package at.asitplus.attestation.android.engine

import at.asitplus.attestation.android.*
import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.attestation.android.exceptions.CertificateInvalidException
import at.asitplus.attestation.android.exceptions.RevocationException
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.encoding.decodeToString
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.asn1
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.CertificateExpiredException
import at.asitplus.signum.indispensable.pki.CertificateNotYetValidException
import at.asitplus.signum.indispensable.pki.CertificateTimeValidityException
import at.asitplus.signum.indispensable.pki.Name
import at.asitplus.signum.indispensable.pki.TrustAnchor
import at.asitplus.signum.indispensable.pki.validate.AnchoredCertificateChain
import at.asitplus.signum.indispensable.pki.validate.CertificateChainValidator
import at.asitplus.signum.indispensable.pki.validate.CertificateValidationContext
import at.asitplus.signum.indispensable.pki.validate.CertificateValidator
import at.asitplus.signum.indispensable.sign.verifierFor
import at.asitplus.signum.indispensable.sign.verify
import at.asitplus.signum.supreme.installSupreme
import kotlin.time.Instant

/** Validates the supplied leaf-first Android chain without path building or Java certificate conversion. */
class SupremeCertChainValidator(private val attestationConfiguration: AndroidAttestationConfiguration) : CertChainValidator {
    init { Signum.installSupreme() }

    override val revocationCheckers: List<Pair<AndroidRevocationList.Loader.Configuration<*>, AndroidRevocationList.Loader>> by lazy {
        attestationConfiguration.revocation.map { it to it.createLoader() }
    }

    override suspend fun CertificateChain.verifyCertificateChain(
        verificationDate: Instant,
        actualTrustAnchors: Collection<TrustedRoot>,
        requireRKP: Boolean,
    ): CertificateChainValidation {
        var revocationLists = emptyList<ConfigWithList>()
        val verdict = catching {
            // Preserve the JVM reference's millisecond verification time, including revocation snapshots.
            val date = Instant.fromEpochMilliseconds(verificationDate.toEpochMilliseconds())
            val root = last()
            val trustedRoot = resolveRoot(actualTrustAnchors)
            val verifyValidity = isRemoteKeyProvisioned() ||
                ((trustedRoot as? TrustedRoot.AndroidSpecific)?.enforceFactoryProvisionedChainValidity
                    ?: attestationConfiguration.enforceFactoryProvisionedChainValidity)
            if (verifyValidity) catchingUnwrapped { root.checkTime(date) }.getOrElse {
                throw CertificateInvalidException.InvalidRoot(
                    "Could not verify root validity", cause = it, reason = CertificateInvalidException.Reason.TIME,
                    certificateChain = this, invalidCertificate = root,
                )
            }

            // Exact certificate/key pin selection precedes the key/name anchor used for Android path checks.
            val anchor = TrustAnchor.PublicKey(trustedRoot.cryptoPublicKey, when (trustedRoot) {
                is TrustedRoot.Certificate -> trustedRoot.value.tbsCertificate.subjectName
                is TrustedRoot.PublicKey -> trustedRoot.name ?: root.tbsCertificate.issuerName
            })
            AndroidPathValidator(this, verifyValidity) { revocationLists = it }.validate(
                AnchoredCertificateChain(dropLast(1), anchor),
                CertificateValidationContext(date = date, trustAnchors = setOf(anchor)),
            )
            if (requireRKP && !isRemoteKeyProvisioned()) throw AttestationValueException(
                "Certificate chain does not contain a remotely-provisioned attestation certificate",
                reason = AttestationValueException.Reason.SEC_LEVEL, expectedValue = true, actualValue = false,
            )
            securityLevel()
        }
        return CertificateChainValidation(verdict, revocationLists)
    }

    private suspend fun CertificateChain.resolveRoot(roots: Collection<TrustedRoot>): TrustedRoot {
        val root = last()
        val rootKey = root.publicKey.asn1.toDer()
        val trusted = roots.filterIsInstance<TrustedRoot.Certificate>().firstOrNull { root.asn1.toDer().contentEquals(it.derEncoded) }
            ?: roots.filterIsInstance<TrustedRoot.PublicKey>().firstOrNull { rootKey.contentEquals(it.derEncoded) }
            ?: run {
                val stage = when {
                    GOOGLE_DEFAULT_HARDWARE_TRUST_ANCHORS.any { rootKey.contentEquals(it.cryptoPublicKey.asn1.toDer()) } ->
                        CertificateInvalidException.OtherMatchingRoot.Stage.HARDWARE
                    GOOGLE_SOFTWARE_TRUST_ANCHORS_UNTIL_A12.any { rootKey.contentEquals(it.cryptoPublicKey.asn1.toDer()) } ->
                        CertificateInvalidException.OtherMatchingRoot.Stage.SOFTWARE
                    else -> null
                }
                throw if (stage == null) CertificateInvalidException.NoMatchingRoot(
                    "No matching root certificate. Found an unknown Root", certificateChain = this, invalidCertificate = root,
                ) else CertificateInvalidException.OtherMatchingRoot(
                    "No matching root certificate. Found a default $stage Root", certificateChain = this,
                    invalidCertificate = root, rootCertStage = stage,
                )
            }
        catchingUnwrapped { root.signatureAlgorithm.verifierFor(trusted.cryptoPublicKey).verify(root) }.getOrElse {
            throw CertificateInvalidException.InvalidRoot(
                "Could not verify root certificate", cause = it, reason = CertificateInvalidException.Reason.TRUST,
                certificateChain = this, invalidCertificate = root,
            )
        }
        return trusted
    }

    private inner class AndroidPathValidator(
        private val chain: CertificateChain,
        private val verifyValidity: Boolean,
        private val onRevocationLists: (List<ConfigWithList>) -> Unit,
    ) : CertificateChainValidator {
        override suspend fun validate(
            anchoredChain: AnchoredCertificateChain,
            context: CertificateValidationContext,
        ): Map<Certificate, Set<ObjectIdentifier>> {
            val path = anchoredChain.validationPath.toList()
            val revocation = RevocationValidator(chain, context.date, onRevocationLists)
            var parent = chain.last()
            path.forEachIndexed { index, certificate ->
                catchingUnwrapped {
                    if (verifyValidity && !(index == path.lastIndex && attestationConfiguration.ignoreLeafValidity)) {
                        certificate.checkTime(context.date)
                    }
                    certificate.signatureAlgorithm.verifierFor(parent.publicKey).verify(certificate)
                }.getOrElse {
                    throw CertificateInvalidException(
                        "Certificate ${certificate.tbsCertificate.serialNumber} could not be verified", cause = it,
                        reason = if (it is CertificateTimeValidityException) CertificateInvalidException.Reason.TIME
                            else CertificateInvalidException.Reason.TRUST,
                        certificateChain = chain, invalidCertificate = certificate,
                    )
                }
                revocation.check(certificate)
                parent = certificate
            }

            catchingUnwrapped {
                require(chain.size >= 3) { "At least 3 certificates are required" }
                require(chain.last().tbsCertificate.issuerName.matches(chain.last().tbsCertificate.subjectName)) {
                    "Root certificate is not self-issued"
                }
                val targetIndex = when {
                    chain.isFactoryProvisioned() -> 2
                    chain.isRemoteKeyProvisioned() -> 3
                    chain.size == 4 -> 2 // The reference also accepts this legacy factory shape without a serial-number RDN.
                    else -> 1
                }
                var issuer = requireNotNull(anchoredChain.trustAnchor.principal)
                path.forEachIndexed { index, certificate ->
                    require(index <= targetIndex) { "Unexpected certificate after the target certificate" }
                    require(certificate.tbsCertificate.issuerName.matches(issuer)) { "Subject/issuer name chaining check failed" }
                    val hasAttestation = certificate.tbsCertificate.extensions.any { it.oid == AttestationKeyDescription.oid }
                    require(hasAttestation == (index == targetIndex)) { "Unexpected attestation extension placement" }
                    issuer = certificate.tbsCertificate.subjectName
                }
            }.getOrElse {
                throw CertificateInvalidException(
                    "Android cert path validation failed", cause = it, reason = CertificateInvalidException.Reason.TRUST,
                    certificateChain = chain, invalidCertificate = null,
                )
            }
            // Android compatibility rules do not impose generic PKIX CA/KU or critical-extension policies.
            return emptyMap()
        }
    }

    private inner class RevocationValidator(
        private val chain: CertificateChain,
        private val date: Instant,
        private val onRevocationLists: (List<ConfigWithList>) -> Unit,
    ) : CertificateValidator {
        override suspend fun check(currCert: Certificate): Set<ObjectIdentifier> {
            if (revocationCheckers.isEmpty()) return emptySet()
            val lists = catchingUnwrapped {
                revocationCheckers.map { (config, loader) -> ConfigWithList(config, loader.load(date)) }
            }.getOrElse { throw RevocationException.ListUnavailable("Could not init revocation list", it) }
            onRevocationLists(lists)
            lists.forEach { snapshot ->
                snapshot.list.find(currCert.tbsCertificate.serialNumber.toString(16))?.let { entry ->
                    throw RevocationException.Revoked(
                        "Certificate ${currCert.tbsCertificate.serialNumber} revoked", certificateChain = chain,
                        revokedCertificate = currCert, entry = entry,
                    )
                }
            }
            return emptySet()
        }
    }

    private fun CertificateChain.isFactoryProvisioned(): Boolean = get(size - 2).tbsCertificate.subjectName
        .relativeDistinguishedNames.any { rdn -> rdn.attrsAndValues.any { it.oid == AttributeTypeAndValue.OID.serialNumber } }

    private fun CertificateChain.securityLevel(): GeneralizedSecurityLevel = when {
        isFactoryProvisioned() -> if (listOf(get(1), get(size - 2)).any {
            "strongbox" in it.tbsCertificate.subjectName.toRfc2253String()
        }) GeneralizedSecurityLevel.STRONGBOX else GeneralizedSecurityLevel.SOFTWARE
        isRemoteKeyProvisioned() -> when (get(1).tbsCertificate.subjectName.relativeDistinguishedNames
            .flatMap { it.attrsAndValues }.lastOrNull { it.oid == AttributeTypeAndValue.OID.organizationName }
            ?.asn1?.toRepresentation()?.value?.asPrimitive()?.decodeToString()) {
            "TEE" -> GeneralizedSecurityLevel.TEE
            "StrongBox" -> GeneralizedSecurityLevel.STRONGBOX
            else -> GeneralizedSecurityLevel.SOFTWARE
        }
        else -> GeneralizedSecurityLevel.SOFTWARE
    }

    private fun Name.matches(other: Name): Boolean = toRfc2253String() == other.toRfc2253String()

    private fun Certificate.checkTime(date: Instant) {
        if (date < tbsCertificate.validFrom) throw CertificateNotYetValidException(tbsCertificate.validFrom, date)
        if (date > tbsCertificate.validUntil) throw CertificateExpiredException(tbsCertificate.validUntil, date)
    }
}
