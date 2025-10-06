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
import org.bouncycastle.asn1.x500.X500Name
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
        vendorPatchLevel: Int?=null,
        verifiedBootKey: ByteArray = Random.nextBytes(32),
        verifiedBootHash: ByteArray = Random.nextBytes(32),
        creationTime: Date = Date(),
    ): List<X509Certificate> = create(
        KeyAttestationDefs(
            attestationVersion = 4,
            attestationSecurityLevel = SecurityLevel.TEE,
            keymasterVersion = 4,
            keymasterSecurityLevel = SecurityLevel.TEE,
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
                    deviceLocked = true,
                    verifiedBootState = BootState.VERIFIED,
                    verifiedBootHash = verifiedBootHash,
                ),
                androidVersion = androidVersion,
                androidPatchLevel = androidPatchLevel,
                vendorPatchLevel = vendorPatchLevel,
            )
        ),
        certificateCreation = creationTime,
    )

    private fun create(keyAttestation: KeyAttestationDefs, certificateCreation: Date): List<X509Certificate> {
        val rootKeyPair = KeyPairGenerator.getInstance("EC").also {
            it.initialize(256)
        }.genKeyPair()
        val rootCert = X509v3CertificateBuilder(
            /* issuer = */ X500Name("CN=Root"),
            /* serial = */ BigInteger.valueOf(Random.nextLong()),
            /* notBefore = */ certificateCreation,
            /* notAfter = */ Date(certificateCreation.time + 1000L * 60L * 60L /* = 60 minutes */),
            /* subject = */ X500Name("CN=Root"),
            /* publicKeyInfo = */ rootKeyPair.subjectPublicKeyInfo()
        ).build(rootKeyPair.contentSigner()).toX509Certificate()

        val intermediateKeyPair = KeyPairGenerator.getInstance("EC").also {
            it.initialize(256)
        }.genKeyPair()
        val intermediateCert = X509v3CertificateBuilder(
            /* issuer = */ X500Name("CN=Root"),
            /* serial = */ BigInteger.valueOf(Random.nextLong()),
            /* notBefore = */ certificateCreation,
            /* notAfter = */ Date(certificateCreation.time + 1000L * 60L * 60L /* = 60 minutes */),
            /* subject = */ X500Name("CN=Intermediate"),
            /* publicKeyInfo = */ intermediateKeyPair.subjectPublicKeyInfo()
        ).build(rootKeyPair.contentSigner()).toX509Certificate()

        val leafKeyPair = KeyPairGenerator.getInstance("EC").also {
            it.initialize(256)
        }.genKeyPair()
        val leafCert = X509v3CertificateBuilder(
            /* issuer = */ X500Name("CN=Intermediate"),
            /* serial = */ BigInteger.valueOf(Random.nextLong()),
            /* notBefore = */ certificateCreation,
            /* notAfter = */ Date(certificateCreation.time + 1000L * 60L * 60L /* = 60 minutes */),
            /* subject = */ X500Name("CN=Subject"),
            /* publicKeyInfo = */ leafKeyPair.subjectPublicKeyInfo()
        ).addExtension(
            ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"),
            false,
            keyAttestation.toSequence()
        ).build(intermediateKeyPair.contentSigner()).toX509Certificate()

        return listOf(leafCert, intermediateCert, rootCert)
    }
}

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
