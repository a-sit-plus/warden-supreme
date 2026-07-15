package at.asitplus.attestation.data

import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.DERUTF8String
import org.bouncycastle.asn1.x500.RDN
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Date
import kotlin.random.Random

object AttestationCreator {
    /**
     * Creates a list of certificates, with the first certificate containing an Android Key Attestation Statement
     * (as an X.509 extension), with values of the attestation as passed in the parameters.
     */
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
    ): List<X509Certificate> = createAttestationWithKeys(
        challenge,
        packageName,
        signatureDigest,
        appVersion,
        androidVersion,
        androidPatchLevel,
        vendorPatchLevel,
        verifiedBootKey,
        deviceLocked,
        verifiedBootState,
        verifiedBootHash,
        creationTime,
        securityLevel = securityLevel,
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
    ): CreatedAttestation = create(
        KeyAttestationDefs(
            attestationVersion = 4,
            // The security level advertised in the extension must match the one the verifier infers
            // from the certificate chain (see create()), otherwise verification fails with a
            // "security level does not match" error.
            attestationSecurityLevel = securityLevel,
            keymasterVersion = 4,
            keymasterSecurityLevel = securityLevel,
            attestationChallenge = challenge,
            uniqueId = byteArrayOf(),
            softwareEnforced = SecurityProperties(
                creationDateTime = Instant.ofEpochMilli(creationTime.time),
                applicationInfo = KeyAttestationApplicationInfo(
                    packageName = packageName,
                    version = appVersion,
                    signatureDigests = listOf(signatureDigest)
                )
            ),
            teeEnforced = SecurityProperties(
                keySize = 256,
                rootOfTrust = RootOfTrust(
                    verifiedBootKey = verifiedBootKey,
                    deviceLocked = deviceLocked,
                    verifiedBootState = verifiedBootState,
                    verifiedBootHash = verifiedBootHash,
                ),
                androidVersion = androidVersion,
                androidPatchLevel = androidPatchLevel,
                vendorPatchLevel = vendorPatchLevel,
            )
        ),
        certificateCreation = creationTime,
        securityLevel = securityLevel,
        attestationLeafCanSignCertificates = attestationLeafCanSignCertificates,
        reuse = reuse,
    )

    /**
     * Builds a certificate chain whose shape and subject DNs match the [securityLevel], so that the
     * verifier infers the same level from the chain that the attestation extension advertises.
     *
     * - [SecurityLevel.SOFTWARE] produces `ROOT -> ATTESTATION -> TARGET` (3 certs). The attestation
     *   certificate carries no distinguishing subject, so the chain parses as software-backed.
     * - [SecurityLevel.TEE] / [SecurityLevel.STRONGBOX] produce a factory-provisioned chain
     *   `ROOT -> FACTORY_INTERMEDIATE -> ATTESTATION -> TARGET` (4 certs). The factory intermediate's
     *   subject encodes the level via a serialNumber (OID 2.5.4.5) plus a title (OID 2.5.4.12) of
     *   exactly `"TEE"` or `"StrongBox"`, which is what `KeyAttestationCertPath.securityLevel()` reads.
     *
     * When [reuse] is supplied, the root and factory intermediate are taken as-is instead of being
     * generated, so multiple attestations can share (and chain up to) the same trusted root — useful
     * for negative tests that must stay under a trusted anchor while varying the attestation content.
     */
    private fun create(
        keyAttestation: KeyAttestationDefs,
        certificateCreation: Date,
        securityLevel: SecurityLevel,
        attestationLeafCanSignCertificates: Boolean,
        reuse: ProvisioningAuthority? = null,
    ): CreatedAttestation {
        val notAfter = Date(certificateCreation.time + 1000L * 60L * 60L /* = 60 minutes */)

        fun ecKeyPair() = KeyPairGenerator.getInstance("EC").also { it.initialize(256) }.genKeyPair()

        fun issue(
            issuer: X500Name,
            subject: X500Name,
            subjectKeyPair: KeyPair,
            signingKeyPair: KeyPair,
            configure: (X509v3CertificateBuilder.() -> Unit)? = null,
        ): X509Certificate = X509v3CertificateBuilder(
            /* issuer = */ issuer,
            /* serial = */ BigInteger.valueOf(Random.nextLong()),
            /* notBefore = */ certificateCreation,
            /* notAfter = */ notAfter,
            /* subject = */ subject,
            /* publicKeyInfo = */ subjectKeyPair.subjectPublicKeyInfo()
        ).apply { configure?.invoke(this) }
            .build(signingKeyPair.contentSigner()).toX509Certificate()

        // The factory-provisioned title the verifier matches against; null means software-backed.
        val factoryTitle = when (securityLevel) {
            SecurityLevel.TEE -> "TEE"
            SecurityLevel.STRONGBOX -> "StrongBox"
            else -> null
        }

        val rootKeyPair: KeyPair
        val rootCert: X509Certificate
        // For factory-provisioned chains, a FACTORY_INTERMEDIATE sits between root and the attestation
        // certificate; its subject encodes the security level. Software-backed chains have no such
        // certificate and the attestation cert is issued directly by the root.
        val intermediateKeyPair: KeyPair
        val factoryIntermediateCert: X509Certificate?
        val attestationIssuerName: X500Name
        val attestationSigningKeyPair: KeyPair
        if (reuse != null) {
            // Reused authorities are always factory-provisioned (they carry a FACTORY_INTERMEDIATE).
            rootKeyPair = reuse.rootKeyPair
            rootCert = reuse.rootCertificate
            intermediateKeyPair = reuse.intermediateKeyPair
            factoryIntermediateCert = reuse.intermediateCertificate
            attestationIssuerName = X500Name.getInstance(reuse.intermediateCertificate.subjectX500Principal.encoded)
            attestationSigningKeyPair = reuse.intermediateKeyPair
        } else {
            rootKeyPair = ecKeyPair()
            val rootName = X500Name("CN=Root")
            rootCert = issue(rootName, rootName, rootKeyPair, rootKeyPair)
            intermediateKeyPair = ecKeyPair()
            if (factoryTitle != null) {
                val factoryIntermediateSubject = X500Name(
                    arrayOf(
                        RDN(ASN1ObjectIdentifier("2.5.4.5"), DERUTF8String(BigInteger.valueOf(Random.nextLong()).toString(16))),
                        RDN(ASN1ObjectIdentifier("2.5.4.12"), DERUTF8String(factoryTitle))
                    )
                )
                factoryIntermediateCert =
                    issue(rootName, factoryIntermediateSubject, intermediateKeyPair, rootKeyPair)
                attestationIssuerName = factoryIntermediateSubject
                attestationSigningKeyPair = intermediateKeyPair
            } else {
                factoryIntermediateCert = null
                attestationIssuerName = rootName
                attestationSigningKeyPair = rootKeyPair
            }
        }

        val attestationKeyPair = ecKeyPair()
        val attestationSubject = X500Name("CN=Attestation")
        val attestationCert =
            issue(attestationIssuerName, attestationSubject, attestationKeyPair, attestationSigningKeyPair)

        val leafKeyPair = ecKeyPair()
        val leafCert = issue(
            issuer = attestationSubject,
            subject = X500Name("CN=Subject"),
            subjectKeyPair = leafKeyPair,
            signingKeyPair = attestationKeyPair,
        ) {
            addExtension(
                ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"),
                false,
                keyAttestation.toSequence()
            )
            if (attestationLeafCanSignCertificates) {
                addExtension(ASN1ObjectIdentifier("2.5.29.19"), true, BasicConstraints(true))
                addExtension(ASN1ObjectIdentifier("2.5.29.15"), true, KeyUsage(KeyUsage.keyCertSign))
            }
        }

        val certificateChain = buildList {
            add(leafCert)
            add(attestationCert)
            factoryIntermediateCert?.let { add(it) }
            add(rootCert)
        }

        return CreatedAttestation(
            certificateChain = certificateChain,
            leafKeyPair = leafKeyPair,
            // For factory chains this is the FACTORY_INTERMEDIATE key; for software chains there is no
            // dedicated intermediate, so we surface the attestation certificate's key.
            intermediateKeyPair = if (factoryIntermediateCert != null) intermediateKeyPair else attestationKeyPair,
            rootKeyPair = rootKeyPair,
            rootCertificate = rootCert,
            factoryIntermediateCertificate = factoryIntermediateCert,
        )
    }
}

data class CreatedAttestation(
    val certificateChain: List<X509Certificate>,
    val leafKeyPair: KeyPair,
    val intermediateKeyPair: KeyPair,
    val rootKeyPair: KeyPair,
    val rootCertificate: X509Certificate,
    /** The FACTORY_INTERMEDIATE certificate for TEE/StrongBox chains; `null` for software-backed chains. */
    val factoryIntermediateCertificate: X509Certificate? = null,
) {
    /**
     * The root + factory intermediate of this (factory-provisioned) chain, for issuing further
     * attestations under the same trust anchor via [AttestationCreator.createAttestationWithKeys]'s
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

private fun X509CertificateHolder.toX509Certificate(): X509Certificate =
    CertificateFactory.getInstance("X.509").generateCertificate(this.encoded.inputStream()) as X509Certificate

private fun KeyPair.contentSigner(): ContentSigner? =
    JcaContentSignerBuilder("SHA256withECDSA").build(private)

private fun KeyPair.subjectPublicKeyInfo(): SubjectPublicKeyInfo? =
    SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(public.encoded))

data class KeyAttestationDefs(
    val attestationVersion: Long,
    val attestationSecurityLevel: SecurityLevel,
    val keymasterVersion: Long,
    val keymasterSecurityLevel: SecurityLevel,
    val attestationChallenge: ByteArray,
    val uniqueId: ByteArray,
    val softwareEnforced: SecurityProperties,
    val teeEnforced: SecurityProperties,
) {
    fun toSequence(): DERSequence = DERSequence(
        arrayOf(
            ASN1Integer(attestationVersion),
            ASN1Enumerated(attestationSecurityLevel.value),
            ASN1Integer(keymasterVersion),
            ASN1Enumerated(keymasterSecurityLevel.value),
            DEROctetString(attestationChallenge),
            DEROctetString(uniqueId),
            softwareEnforced.toSequence(),
            teeEnforced.toSequence()
        )
    )
}

data class SecurityProperties(
    val creationDateTime: Instant? = null,
    val keySize: Int? = null,
    val applicationInfo: KeyAttestationApplicationInfo? = null,
    val androidVersion: Int? = null,
    val androidPatchLevel: Int? = null,
    val vendorPatchLevel: Int? = null,
    val rootOfTrust: RootOfTrust? = null,
) {
    fun toSequence(): DERSequence =
        DERSequence(
            arrayOf(
                creationDateTime?.let { DERTaggedObject(701, ASN1Integer(it.toEpochMilli())) },
                keySize?.let { DERTaggedObject(3, ASN1Integer(it.toLong())) },
                rootOfTrust?.let { DERTaggedObject(704, it.encoded()) },
                androidVersion?.let { DERTaggedObject(705, ASN1Integer(it.toLong())) },
                androidPatchLevel?.let { DERTaggedObject(706, ASN1Integer(it.toLong())) },
                applicationInfo?.let { DERTaggedObject(709, DEROctetString(it.encoded())) },
                vendorPatchLevel?.let { DERTaggedObject(718, ASN1Integer(it.toLong())) },
            ).filterNotNull().toTypedArray()
        )
}

data class KeyAttestationApplicationInfo(
    val packageName: String,
    val version: Int,
    val signatureDigests: Collection<ByteArray>
) {
    fun encoded(): ByteArray = DERSequence(
        arrayOf(
            DERSet(
                DERSequence(
                    arrayOf(
                        DEROctetString(packageName.encodeToByteArray()),
                        ASN1Integer(version.toLong())
                    )
                )
            ),
            DERSet(
                signatureDigests.map { DEROctetString(it) }.toTypedArray()
            )
        )
    ).encoded
}

data class RootOfTrust(
    val verifiedBootKey: ByteArray,
    val deviceLocked: Boolean,
    val verifiedBootState: BootState,
    val verifiedBootHash: ByteArray
) {
    fun encoded(): DERSequence = DERSequence(
        arrayOf(
            DEROctetString(verifiedBootKey),
            ASN1Boolean.getInstance(deviceLocked),
            ASN1Enumerated(verifiedBootState.value),
            DEROctetString(verifiedBootHash)
        )
    )
}

enum class SecurityLevel(val value: Int) {
    NULL(-1),
    SOFTWARE(0),
    TEE(1),
    STRONGBOX(2);

    companion object {
        fun valueOf(value: Int?): SecurityLevel = values().find { it.value == value } ?: NULL
    }
}


enum class BootState(val value: Int) {
    NULL(-1),
    VERIFIED(0),
    SELF_SIGNED(1),
    UNVERIFIED(2),
    FAILED(3);

    companion object {
        fun valueOf(value: Int?): BootState = values().find { it.value == value } ?: NULL
    }
}

enum class KeyOrigin(val value: Int) {
    NULL(-1),
    GENERATED(0),
    DERIVED(1),
    IMPORTED(2),
    UNKNOWN(3);

    companion object {
        fun valueOf(value: Int?): KeyOrigin = values().find { it.value == value } ?: NULL
    }
}

enum class Purpose(val value: Int) {
    NULL(-1),
    ENCRYPT(0),
    DECRYPT(1),
    SIGN(2),
    VERIFY(3),
    DERIVE_KEY(4),
    WRAP_KEY(5);

    companion object {
        fun valueOf(value: Int?): Purpose = values().find { it.value == value } ?: NULL
    }
}

enum class Algorithm(val value: Int) {
    NULL(-1),
    RSA(1),
    DSA(2),
    EC(3),
    AES(32),
    TRIPLE_DES(33),
    HMAC(128);

    companion object {
        fun valueOf(value: Int?): Algorithm = values().find { it.value == value } ?: NULL
    }
}

enum class Digest(val value: Int) {
    NULL(-1),
    NONE(0),
    MD5(1),
    SHA1(2),
    SHA224(3),
    SHA256(4),
    SHA384(5),
    SHA512(6);

    companion object {
        fun valueOf(value: Int?): Digest = values().find { it.value == value } ?: NULL
    }
}

enum class Padding(val value: Int) {
    NULL(-1),
    NONE(1),
    RSA_OAEP(2),
    RSA_PSS(3),
    PKCS1_15_ENCRYPT(4),
    PKCS1_15_SIGN(5),
    PKCS7(64);

    companion object {
        fun valueOf(value: Int?): Padding = values().find { it.value == value } ?: NULL
    }
}

enum class Curve(val value: Int) {
    NULL(-1),
    P224(0),
    P256(1),
    P384(2),
    P512(3);

    companion object {
        fun valueOf(value: Int?): Curve = values().find { it.value == value } ?: NULL
    }
}

enum class Auth(val value: Int) {
    NULL(-1),
    NONE(0),
    PASSWORD(1),
    FINGERPRINT(2);

    companion object {
        fun valueOf(value: Int?): Auth = values().find { it.value == value } ?: NULL
    }
}
