@file:OptIn(at.asitplus.signum.indispensable.SecretExposure::class)

package at.asitplus.attestation.creator

import at.asitplus.attestation.android.AttestationKeyDescription
import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.Asn1Time
import at.asitplus.signum.indispensable.asn1.BitSet
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.encodeToPEM
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.signum.supreme.sign
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.supreme.sign.signerFor
import kotlinx.coroutines.runBlocking
import kotlin.random.Random
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

/**
 * The runtime counterpart of [IssuerSpec]: a root, an attestation CA chain, and the keys to sign with.
 *
 * All crypto material lives here and nowhere else; [spec] is the configuration that produced it, with
 * a generated root filled back in, so `CreatorConfig(issuer.spec, …)` reproduces this issuer exactly.
 *
 * Every [issue] call mints a fresh attestation key and a fresh attested leaf key, as real devices do.
 */
class AndroidAttestationIssuer private constructor(
    val spec: IssuerSpec,
    private val root: CertifiedKey,
    /** Signs the per-issuance attestation key. Bottom-most CA of [caChain]. */
    private val attestationCa: CertifiedKey,
    /** The CA certificates between leaf and root, ordered leaf-most first. */
    private val caChain: List<X509Certificate>,
) {
    val rootCertificate: X509Certificate get() = root.certificate

    /** The configuration reproducing this issuer, together with the attestations to create from it. */
    fun configuration(
        attestations: List<AttestationSpec> = listOf(AttestationSpec()),
        outputDirectory: String = "creator-output",
    ) = CreatorConfig(spec, attestations, outputDirectory)

    fun issue(attestation: AttestationSpec = AttestationSpec()): IssuedAttestation {
        val validity = validityFrom(attestation.createdAt)
        val attestationKey = attestationCa.certifySubordinateCa("Android Keystore Attestation", validity, pathLength = 0)
        val leafKey = ephemeralEcP256Signer()
        val leaf = attestationKey.certify(
            subject = commonName("Android Keystore Key"),
            subjectKey = leafKey.publicKey,
            validity = validity,
            role = Role.EndEntity,
            extensions = listOf(attestation.keyDescription.asCertificateExtension()),
        )
        return IssuedAttestation(
            certificateChain = listOf(leaf, attestationKey.certificate) + caChain + root.certificate,
            leafSigner = leafKey,
        )
    }

    /** Builds the statement with the type-safe DSL instead of passing a prepared [AttestationSpec]. */
    fun issue(block: AttestationSpecBuilder.() -> Unit): IssuedAttestation =
        issue(AttestationSpecBuilder().apply(block).build())

    companion object {
        fun from(spec: IssuerSpec): AndroidAttestationIssuer {
            val validity = validityFrom(spec.issuedAt)
            val (root, rootSpec) = spec.root?.let { it.load() to it }
                ?: selfSignedRoot(validity).let { it to it.export() }
            // Every CA below the root states exactly how many CA certificates may follow it: the
            // remaining intermediates plus the per-issuance attestation certificate.
            val names = spec.caNames
            val cas = names.foldIndexed(listOf<CertifiedKey>()) { index, chain, name ->
                chain + (chain.lastOrNull() ?: root)
                    .certifySubordinateCa(name, validity, pathLength = names.size - index)
            }
            return AndroidAttestationIssuer(
                spec = spec.copy(root = rootSpec),
                root = root,
                attestationCa = cas.last(),
                caChain = cas.asReversed().map { it.certificate },
            )
        }
    }
}

/** One issued attestation: the chain a client would present, and the attested leaf key. */
data class IssuedAttestation(
    /** Leaf first, root last. */
    val certificateChain: List<X509Certificate>,
    /** The attested private key, for signing payloads the attestation vouches for. */
    val leafSigner: Signer,
) {
    val leafCertificate: X509Certificate get() = certificateChain.first()
    val rootCertificate: X509Certificate get() = certificateChain.last()

    fun chainPem(): String = certificateChain.joinToString("\n") { it.encodeToPEM().getOrThrow() }
    fun leafPrivateKeyPem(): String = leafSigner.exportPrivateKey().getOrThrow().encodeToPEM().getOrThrow()
}

/** Certificate validity: not-before and not-after. */
internal typealias Validity = Pair<Asn1Time, Asn1Time>

/** A private key together with the certificate that binds it: the unit an issuer actually signs with. */
internal class CertifiedKey(val certificate: X509Certificate, val signer: Signer) {
    val subject: List<RelativeDistinguishedName> get() = certificate.tbsCertificate.subjectName

    fun certify(
        subject: List<RelativeDistinguishedName>,
        subjectKey: CryptoPublicKey,
        validity: Validity,
        role: Role,
        extensions: List<X509CertificateExtension> = emptyList(),
    ): X509Certificate = issueCertificate(
        issuer = this.subject,
        subject = subject,
        subjectKey = subjectKey,
        signer = signer,
        validity = validity,
        extensions = role.extensions(subjectKey, signer.publicKey) + extensions,
    )

    /** Generates a fresh key and certifies it as a CA under this one. */
    fun certifySubordinateCa(name: String, validity: Validity, pathLength: Int?): CertifiedKey =
        ephemeralEcP256Signer().let {
            CertifiedKey(certify(commonName(name), it.publicKey, validity, Role.CertificateAuthority(pathLength)), it)
        }

    /** This key as reusable configuration. */
    fun export() = RootSpec(
        certificatePem = certificate.encodeToPEM().getOrThrow(),
        privateKeyPkcs8Pem = signer.exportPrivateKey().getOrThrow().encodeToPEM().getOrThrow(),
    )
}

private val IssuerSpec.caNames: List<String>
    get() = when (provisioning) {
        Provisioning.FACTORY -> listOf("${securityLevel.caName} Attestation")
        Provisioning.RKP -> listOf("Droid CA2", "Droid CA3")
    }

private val AttestationKeyDescription.SecurityLevel.caName: String
    get() = if (this == AttestationKeyDescription.SecurityLevel.STRONGBOX) "StrongBox" else "TEE"

private fun RootSpec.load(): CertifiedKey {
    val certificate = X509Certificate.decodeFromPem(certificatePem).getOrThrow()
    val key = CryptoPrivateKey.decodeFromPem(privateKeyPkcs8Pem).getOrThrow() as? CryptoPrivateKey.WithPublicKey<*>
        ?: error("Imported root private key carries no public key")
    require(key.publicKey == certificate.decodedPublicKey.getOrThrow()) {
        "Imported root certificate does not match its private key"
    }
    return CertifiedKey(certificate, SignatureAlgorithm.ECDSA(Digest.SHA256, null).signerFor(key).getOrThrow())
}

/** Roots state `CA:TRUE` without a path-length constraint, the way Google's attestation root does. */
private fun selfSignedRoot(validity: Validity): CertifiedKey = ephemeralEcP256Signer().let { signer ->
    val subject = commonName("Creator Test Root")
    val role = Role.CertificateAuthority(pathLength = null)
    CertifiedKey(
        issueCertificate(
            issuer = subject,
            subject = subject,
            subjectKey = signer.publicKey,
            signer = signer,
            validity = validity,
            extensions = role.extensions(signer.publicKey, signer.publicKey),
        ),
        signer,
    )
}

/**
 * What a certificate is for, and therefore which RFC 5280 extensions it carries.
 *
 * Real attestation chains are ordinary, compliant X.509: without these, strict path validation
 * (OpenSSL's included) rejects the chain outright with *invalid CA certificate*.
 */
internal sealed interface Role {
    /** @param pathLength how many CA certificates may follow; `null` leaves it unconstrained. */
    data class CertificateAuthority(val pathLength: Int?) : Role

    data object EndEntity : Role

    fun extensions(subjectKey: CryptoPublicKey, issuerKey: CryptoPublicKey): List<X509CertificateExtension> =
        listOf(subjectKeyIdentifier(subjectKey), authorityKeyIdentifier(issuerKey)) + when (this) {
            is CertificateAuthority -> listOf(basicConstraints(pathLength), keyUsage(KEY_CERT_SIGN, CRL_SIGN))
            EndEntity -> listOf(keyUsage(DIGITAL_SIGNATURE))
        }
}

/** `basicConstraints`: `CA:TRUE`, optionally with a path-length constraint. RFC 5280 4.2.1.9. */
private fun basicConstraints(pathLength: Int?) = extension("2.5.29.19", critical = true) {
    Asn1.Sequence {
        +Asn1.Bool(true)
        pathLength?.let { +Asn1.Int(it) }
    }
}

/** `keyUsage`, as a DER BIT STRING of the given RFC 5280 4.2.1.3 bit positions. */
private fun keyUsage(vararg bits: Long) = extension("2.5.29.15", critical = true) {
    Asn1.BitString(BitSet().apply { bits.forEach { set(it) } })
}

private const val DIGITAL_SIGNATURE = 0L
private const val KEY_CERT_SIGN = 5L
private const val CRL_SIGN = 6L

/** `subjectKeyIdentifier`. RFC 5280 4.2.1.2. */
private fun subjectKeyIdentifier(subjectKey: CryptoPublicKey) = extension("2.5.29.14") {
    Asn1.OctetString(subjectKey.keyIdentifier())
}

/** `authorityKeyIdentifier`, identifying the issuer by its key. RFC 5280 4.2.1.1. */
private fun authorityKeyIdentifier(issuerKey: CryptoPublicKey) = extension("2.5.29.35") {
    Asn1.Sequence { +Asn1Primitive(Asn1.ImplicitTag(0uL), issuerKey.keyIdentifier()) }
}

/** RFC 5280 method 1: the SHA-1 digest of the `subjectPublicKey` BIT STRING contents. */
private fun CryptoPublicKey.keyIdentifier(): ByteArray {
    // SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey BIT STRING }; the BIT STRING's
    // content starts with its count of unused bits, which is not part of the key.
    val subjectPublicKey = encodeToTlv().children[1].asPrimitive().content
    return Digest.SHA1.digest(subjectPublicKey.copyOfRange(1, subjectPublicKey.size))
}

private fun extension(oid: String, critical: Boolean = false, value: () -> Asn1Element) =
    X509CertificateExtension(ObjectIdentifier(oid), critical, Asn1.OctetStringEncapsulating { +value() })

internal fun AttestationKeyDescription.asCertificateExtension() = X509CertificateExtension(
    AttestationKeyDescription.oid,
    false,
    Asn1.OctetStringEncapsulating { +this@asCertificateExtension },
)

/**
 * 20 random bytes, forced positive and minimally encoded: a random top byte makes DER serial numbers
 * that strict parsers (OpenSSL among them) reject outright.
 */
private fun randomSerialNumber() = byteArrayOf(1) + Random.nextBytes(19)

private fun ephemeralEcP256Signer() = Signer.Ephemeral { ec { } }.getOrThrow()

private fun commonName(value: String) =
    listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(value))))

private fun validityFrom(start: Instant) = Asn1Time(start) to Asn1Time(start + 365.days)

private fun issueCertificate(
    issuer: List<RelativeDistinguishedName>,
    subject: List<RelativeDistinguishedName>,
    subjectKey: CryptoPublicKey,
    signer: Signer,
    validity: Validity,
    extensions: List<X509CertificateExtension> = emptyList(),
): X509Certificate = runBlocking {
    signer.sign(
        TbsCertificate(
            serialNumber = randomSerialNumber(),
            publicKey = subjectKey,
            signatureAlgorithm = signer.signatureAlgorithm.toX509SignatureAlgorithm().getOrThrow(),
            validFrom = validity.first,
            validUntil = validity.second,
            issuerName = issuer,
            subjectName = subject,
            extensions = extensions,
        )
    ).getOrThrow()
}
