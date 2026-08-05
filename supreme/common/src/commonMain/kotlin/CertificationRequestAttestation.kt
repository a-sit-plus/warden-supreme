package at.asitplus.attestation.supreme

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.decodeToInt
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequestAttribute
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.TbsCertificationRequest
import at.asitplus.signum.indispensable.pki.X509CertificateExtension

/**
 * Canonical DER structure authenticated by [DataAuthentication.Hash].
 *
 * It mirrors a [TbsCertificationRequest] while deliberately omitting its public key and the single attestation-proof
 * attribute. [toTbsCsr] adds those two values after key generation; [TbsCertificationRequest.toHashInput] performs the
 * inverse operation. This makes the mapping explicit and keeps hash construction aligned with the actual TBS CSR.
 */
data class AttestationHashInput internal constructor(
    val version: Int = 0,
    val subjectName: List<RelativeDistinguishedName>,
    val attributes: List<Pkcs10CertificationRequestAttribute> = emptyList(),
) : Asn1Encodable<Asn1Sequence> {

    constructor(
        subjectName: List<RelativeDistinguishedName>,
        extensions: List<X509CertificateExtension> = emptyList(),
        version: Int = 0,
        attributes: List<Pkcs10CertificationRequestAttribute> = emptyList(),
    ) : this(
        version,
        subjectName,
        extensions.ifEmpty { null }?.let { extns ->
            attributes + Pkcs10CertificationRequestAttribute(
                KnownOIDs.extensionRequest,
                Asn1.Sequence { extns.forEach { +it } })
        } ?: attributes,
    )

    override fun encodeToTlv() = Asn1.Sequence {
        +Asn1.Int(version)
        +Asn1.Sequence { subjectName.forEach { +it } }
        +(Asn1.SetOf { attributes.forEach { +it } } withImplicitTag 0u)
    }

    /** Completes this hash input with the attested [publicKey] and exactly one [proof] attribute. */
    fun toTbsCsr(
        publicKey: CryptoPublicKey,
        proof: Pkcs10CertificationRequestAttribute,
    ): TbsCertificationRequest {
        require(attributes.none { it.oid == proof.oid }) {
            "Attestation proof attribute already present for OID ${proof.oid}"
        }
        return TbsCertificationRequest(
            version,
            subjectName,
            publicKey,
            (attributes + proof).canonicalized(),
        )
    }

    companion object : Asn1Decodable<Asn1Sequence, AttestationHashInput> {
        override fun doDecode(src: Asn1Sequence) = src.decodeRethrowing {
            val version = next().asPrimitive().decodeToInt()
            val subjectName = next().asSequence().map { RelativeDistinguishedName.decodeFromTlv(it.asSet()) }
            val taggedAttributes = next().asStructure()
            if (taggedAttributes.tag.tagValue != 0uL || taggedAttributes.tag.tagClass != TagClass.CONTEXT_SPECIFIC) {
                throw Asn1StructuralException("Expected implicitly tagged TBS CSR attributes at [0]")
            }
            val attributes = taggedAttributes.map { Pkcs10CertificationRequestAttribute.decodeFromTlv(it.asSequence()) }
            if (hasNext()) throw Asn1StructuralException("Superfluous structure in attestation hash input")
            AttestationHashInput(version, subjectName, attributes)
        }
    }
}

// TODO Remove after Signum canonicalizes PKCS#10's implicitly tagged SET OF attributes.
private fun List<Pkcs10CertificationRequestAttribute>.canonicalized() = Asn1.SetOf {
    forEach { +it }
}.map { Pkcs10CertificationRequestAttribute.decodeFromTlv(it.asSequence()) }

/**
 * Removes the public key and exactly one attestation-proof attribute identified by [proofOid], producing the canonical
 * input used by [DataAuthentication.Hash].
 */
fun TbsCertificationRequest.toHashInput(proofOid: ObjectIdentifier) = AttestationHashInput(
    version,
    subjectName,
    attributes.removeSingle(proofOid),
)

private fun List<Pkcs10CertificationRequestAttribute>.removeSingle(
    oid: ObjectIdentifier,
): List<Pkcs10CertificationRequestAttribute> {
    require(count { it.oid == oid } == 1) { "Expected exactly one attestation proof attribute for OID $oid" }
    return filterNot { it.oid == oid }
}
