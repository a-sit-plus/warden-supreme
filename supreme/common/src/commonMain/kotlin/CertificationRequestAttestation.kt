package at.asitplus.attestation.supreme

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.decodeToInt
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.pki.*
import at.asitplus.awesn1.serialization.encodeToTlv
import at.asitplus.awesn1.serialization.decodeFromTlv

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
    val attributes: List<CsrAttribute> = emptyList(),
) : Asn1Encodable<Asn1Sequence> {

    init { require(version == 0) { "PKCS#10 only supports version 0" } }

    constructor(
        subjectName: List<RelativeDistinguishedName>,
        extensions: List<X509CertificateExtension> = emptyList(),
        version: Int = 0,
        attributes: List<CsrAttribute> = emptyList(),
    ) : this(
        version,
        subjectName,
        extensions.ifEmpty { null }?.let { extns ->
            attributes + CsrAttribute(
                KnownOIDs.extensionRequest,
                Asn1.Sequence { extns.forEach { +Signum.Der.encodeToTlv(it) } })
        } ?: attributes,
    )

    override fun encodeToTlv() = Asn1.Sequence {
        +Asn1.Int(version)
        +Asn1.Sequence { subjectName.forEach { +Signum.Der.encodeToTlv(it) } }
        +(Asn1.SetOf { attributes.forEach { +Signum.Der.encodeToTlv(it) } } withImplicitTag 0u)
    }

    /** Completes this hash input with the attested [publicKey] and exactly one [proof] attribute. */
    fun toTbsCsr(
        publicKey: CryptoPublicKey,
        proof: CsrAttribute,
    ): TbsCertificationRequest {
        require(attributes.none { it.oid == proof.oid }) {
            "Attestation proof attribute already present for OID ${proof.oid}"
        }
        return TbsCertificationRequest(
            X500Name(subjectName),
            publicKey,
            Asn1.SetOf { (attributes + proof).forEach { +Signum.Der.encodeToTlv(it) } }
                .map { Signum.Der.decodeFromTlv<CsrAttribute>(it) },
        )
    }

    companion object : Asn1Decodable<Asn1Sequence, AttestationHashInput> {
        override fun doDecode(src: Asn1Sequence) = src.decodeRethrowing {
            val version = next().asPrimitive().decodeToInt()
            val subjectName = next().asSequence().map { Signum.Der.decodeFromTlv<RelativeDistinguishedName>(it.asSet()) }
            val taggedAttributes = next().asStructure()
            if (taggedAttributes.tag.tagValue != 0uL || taggedAttributes.tag.tagClass != TagClass.CONTEXT_SPECIFIC) {
                throw Asn1StructuralException("Expected implicitly tagged TBS CSR attributes at [0]")
            }
            val attributes = taggedAttributes.map { Signum.Der.decodeFromTlv<CsrAttribute>(it.asSequence()) }
            if (hasNext()) throw Asn1StructuralException("Superfluous structure in attestation hash input")
            AttestationHashInput(version, subjectName, attributes)
        }
    }
}

/**
 * Removes the public key and exactly one attestation-proof attribute identified by [proofOid], producing the canonical
 * input used by [DataAuthentication.Hash].
 */
fun TbsCertificationRequest.toHashInput(proofOid: ObjectIdentifier) = AttestationHashInput(
    0,
    subjectName.relativeDistinguishedNames,
    attributes.removeSingle(proofOid),
)

private fun List<CsrAttribute>.removeSingle(
    oid: ObjectIdentifier,
): List<CsrAttribute> {
    require(count { it.oid == oid } == 1) { "Expected exactly one attestation proof attribute for OID $oid" }
    return filterNot { it.oid == oid }
}
