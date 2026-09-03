@file:OptIn(at.asitplus.signum.indispensable.SecretExposure::class)

package at.asitplus.attestation.data

import at.asitplus.attestation.android.AttestationKeyDescription
import at.asitplus.attestation.android.AuthorizationList
import at.asitplus.attestation.generator.CertifiedKey
import at.asitplus.attestation.generator.Provisioning
import at.asitplus.attestation.generator.RootSpec
import at.asitplus.attestation.generator.androidAttestationIssuer
import at.asitplus.attestation.generator.mangle
import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.asn1.encodeToPEM
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.toJcaCertificateBlocking
import at.asitplus.signum.indispensable.toJcaPrivateKey
import at.asitplus.signum.indispensable.toJcaPublicKey
import at.asitplus.signum.supreme.sign.Signer
import java.security.KeyPair
import java.security.cert.X509Certificate
import java.util.Date
import kotlin.random.Random
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * Fake Android key attestation chains for tests, issued by the generator module (`:generator`).
 *
 * This replaces the hand-rolled BouncyCastle chain builder that used to live here. The parameters and
 * the resulting chain shapes are unchanged, so the tests using them are unchanged too:
 * [SecurityLevel.TEE] and [SecurityLevel.STRONGBOX] give `root -> factory CA -> attestation -> leaf`,
 * where the factory CA and the attestation certificate carry `serialNumber` and `title=TEE|StrongBox`,
 * which is what a verifier reads the security level off.
 *
 * The generator names those certificates the way real Android chains do, rather than the way the old
 * generator did (`CN=Root`, `CN=Attestation`); everything a verifier keys on is the same.
 *
 * Passing [Provisioning] explicitly overrides that mapping -- most interestingly with
 * [Provisioning.RKP], which the old generator could not produce at all.
 */
object FakeAttestations {

    /** The chain only; the first certificate carries the attestation extension. */
    fun createAttestation(
        challenge: ByteArray,
        packageName: String,
        signatureDigest: ByteArray,
        appVersion: Int = 1,
        androidVersion: Int = 11,
        androidPatchLevel: Int = 202108,
        vendorPatchLevel: Int? = null,
        verifiedBootKey: ByteArray = Random.nextBytes(32),
        deviceLocked: Boolean = true,
        verifiedBootState: BootState = BootState.VERIFIED,
        verifiedBootHash: ByteArray = Random.nextBytes(32),
        creationTime: Date = Date(),
        securityLevel: SecurityLevel = SecurityLevel.TEE,
        provisioning: Provisioning? = null,
    ): List<X509Certificate> = createAttestationWithKeys(
        challenge = challenge,
        packageName = packageName,
        signatureDigest = signatureDigest,
        appVersion = appVersion,
        androidVersion = androidVersion,
        androidPatchLevel = androidPatchLevel,
        vendorPatchLevel = vendorPatchLevel,
        verifiedBootKey = verifiedBootKey,
        deviceLocked = deviceLocked,
        verifiedBootState = verifiedBootState,
        verifiedBootHash = verifiedBootHash,
        creationTime = creationTime,
        securityLevel = securityLevel,
        provisioning = provisioning,
    ).certificateChain

    fun createAttestationWithKeys(
        challenge: ByteArray,
        packageName: String,
        signatureDigest: ByteArray,
        appVersion: Int = 1,
        androidVersion: Int = 11,
        androidPatchLevel: Int = 202108,
        vendorPatchLevel: Int? = null,
        verifiedBootKey: ByteArray = Random.nextBytes(32),
        deviceLocked: Boolean = true,
        verifiedBootState: BootState = BootState.VERIFIED,
        verifiedBootHash: ByteArray = Random.nextBytes(32),
        creationTime: Date = Date(),
        securityLevel: SecurityLevel = SecurityLevel.TEE,
        attestationLeafCanSignCertificates: Boolean = false,
        reuse: ProvisioningAuthority? = null,
        /** The chain shape; defaults to what [securityLevel] implies. */
        provisioning: Provisioning? = null,
    ): CreatedAttestation {
        val createdAt = Instant.fromEpochMilliseconds(creationTime.time)

        val issuer = androidAttestationIssuer {
            issuedAt = createdAt
            // The old generator issued everything for exactly one hour; several tests depend on it.
            validity = 60.minutes
            when (provisioning ?: securityLevel.impliedProvisioning) {
                Provisioning.FACTORY -> factoryProvisioned(securityLevel.parsed)
                Provisioning.RKP -> rkp(securityLevel.parsed)
            }
            // Reusing an authority means staying under the same trust anchor; the CAs below it are
            // reissued, since nothing but the anchor is compared.
            reuse?.let { root = it.asRootSpec() }
        }

        val issued = issuer.issue {
            this.createdAt = createdAt
            attestationVersion = 4
            keyMintVersion = 4
            this.securityLevel = securityLevel.parsed
            nonce = challenge
            leafCanSignCertificates = attestationLeafCanSignCertificates

            softwareEnforced = AuthorizationList(
                creationDateTime = AuthorizationList.CreationDateTime(createdAt),
                attestationApplicationId = AuthorizationList.AttestationApplicationId(
                    packageInfos = setOf(
                        AuthorizationList.AttestationPackageInfo(packageName, appVersion.toUInt())
                    ),
                    signatureDigests = setOf(signatureDigest),
                ),
            )
            hardwareEnforced = AuthorizationList(
                keySize = AuthorizationList.KeySize(BitLength(256u)),
                rootOfTrust = AuthorizationList.RootOfTrust(
                    verifiedBootKeyDigest = verifiedBootKey,
                    deviceLocked = deviceLocked,
                    verifiedBootState = verifiedBootState.parsed,
                    verifiedBootHash = verifiedBootHash,
                ),
            )
                // Version and patch levels are plain integers on this API, and devices put values in
                // them that the schema's typed representation cannot hold at all (see "Bug 77", which
                // reports a vendor patch level of 0). They go in as the raw integers they are.
                .withRawInt(AuthorizationList.OsVersion, androidVersion)
                .withRawInt(AuthorizationList.OsPatchLevel, androidPatchLevel)
                .let { list -> vendorPatchLevel?.let { list.withRawInt(AuthorizationList.PatchLevel.Vendor, it) } ?: list }
        }

        return CreatedAttestation(
            certificateChain = issued.certificateChain.map { it.toJava() },
            leafKeyPair = issued.leafSigner.toJavaKeyPair(),
            intermediateKeyPair = issuer.attestationCa.toJavaKeyPair(),
            rootKeyPair = issuer.root.toJavaKeyPair(),
            rootCertificate = issuer.root.certificate.toJava(),
            factoryIntermediateCertificate =
                if (issuer.spec.provisioning == Provisioning.FACTORY) issuer.attestationCa.certificate.toJava() else null,
        )
    }
}

data class CreatedAttestation(
    val certificateChain: List<X509Certificate>,
    val leafKeyPair: KeyPair,
    val intermediateKeyPair: KeyPair,
    val rootKeyPair: KeyPair,
    val rootCertificate: X509Certificate,
    /** The factory CA for TEE/StrongBox chains; `null` for software-backed chains. */
    val factoryIntermediateCertificate: X509Certificate? = null,
) {
    /**
     * The root + factory intermediate of this (factory-provisioned) chain, for issuing further
     * attestations under the same trust anchor via [FakeAttestations.createAttestationWithKeys]'s
     * `reuse` parameter. `null` for software-backed chains, which have no factory intermediate.
     */
    val provisioningAuthority: ProvisioningAuthority?
        get() = factoryIntermediateCertificate?.let {
            ProvisioningAuthority(rootKeyPair, rootCertificate, intermediateKeyPair, it)
        }
}

/** Reusable root + factory intermediate material for chaining multiple attestations to one anchor. */
data class ProvisioningAuthority(
    val rootKeyPair: KeyPair,
    val rootCertificate: X509Certificate,
    val intermediateKeyPair: KeyPair,
    val intermediateCertificate: X509Certificate,
)

enum class SecurityLevel(val value: Int) {
    NULL(-1),
    SOFTWARE(0),
    TEE(1),
    STRONGBOX(2);

    /**
     * Android provisions attestation keys in the factory or remotely, and nothing else -- so that is
     * all the generator builds. The old generator also had a software-backed shape with no attestation
     * CA at all; nothing has ever asked for one, and inventing a third provisioning method to keep it
     * would put a shape in the generator that Android does not have.
     */
    internal val impliedProvisioning: Provisioning
        get() = when (this) {
            TEE, STRONGBOX -> Provisioning.FACTORY
            SOFTWARE, NULL -> throw IllegalArgumentException(
                "No software-backed chains: pick TEE or STRONGBOX, or pass a Provisioning explicitly"
            )
        }

    internal val parsed: AttestationKeyDescription.SecurityLevel
        get() = when (this) {
            STRONGBOX -> AttestationKeyDescription.SecurityLevel.STRONGBOX
            TEE -> AttestationKeyDescription.SecurityLevel.TRUSTED_ENVIRONMENT
            else -> AttestationKeyDescription.SecurityLevel.SOFTWARE
        }

    companion object {
        fun valueOf(value: Int?): SecurityLevel = entries.find { it.value == value } ?: NULL
    }
}

enum class BootState(val value: Int) {
    NULL(-1),
    VERIFIED(0),
    SELF_SIGNED(1),
    UNVERIFIED(2),
    FAILED(3);

    internal val parsed: AuthorizationList.RootOfTrust.VerifiedBootState
        get() = when (this) {
            SELF_SIGNED -> AuthorizationList.RootOfTrust.VerifiedBootState.SelfSigned
            UNVERIFIED -> AuthorizationList.RootOfTrust.VerifiedBootState.Unverified
            FAILED -> AuthorizationList.RootOfTrust.VerifiedBootState.Failed
            else -> AuthorizationList.RootOfTrust.VerifiedBootState.Verified
        }

    companion object {
        fun valueOf(value: Int?): BootState = entries.find { it.value == value } ?: NULL
    }
}

/** Sets [property] to a raw INTEGER, the way a device reports a version or patch level. */
private fun AuthorizationList.withRawInt(property: AuthorizationList.Tagged, value: Int) =
    mangle(property, Asn1.ExplicitlyTagged(property.explicitTag) { +Asn1.Int(value) })

private fun ProvisioningAuthority.asRootSpec() = RootSpec(
    certificatePem = rootCertificate.toKmp().encodeToPEM().getOrThrow(),
    privateKeyPkcs8Pem = CryptoPrivateKey.decodeFromDer(rootKeyPair.private.encoded).encodeToPEM().getOrThrow(),
)

private fun java.security.cert.X509Certificate.toKmp() =
    at.asitplus.signum.indispensable.pki.X509Certificate.decodeFromDer(encoded)

private fun at.asitplus.signum.indispensable.pki.X509Certificate.toJava(): X509Certificate =
    toJcaCertificateBlocking().getOrThrow()

private fun CertifiedKey.toJavaKeyPair(): KeyPair = signer.toJavaKeyPair()

private fun Signer.toJavaKeyPair(): KeyPair {
    val privateKey = exportPrivateKey().getOrThrow() as CryptoPrivateKey.WithPublicKey<*>
    return KeyPair(publicKey.toJcaPublicKey().getOrThrow(), privateKey.toJcaPrivateKey().getOrThrow())
}
