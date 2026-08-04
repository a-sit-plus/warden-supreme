package at.asitplus.attestation.supreme

import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.ExplicitlyTagged


/**
 * Additional client-provided values decoded from the sequence stored in a dedicated TBS CSR attribute.
 */
class AttestedAttributes(val otherAttributesEncoded: Asn1Sequence?) {

    /**
     * Decodes values by their requested position and [PrimitiveType]. Missing optional values decode to `null`;
     * missing required values, unexpected values, and malformed encodings are rejected.
     */
    fun parsedAttributesBy(requestedAttributes: List<AttestationChallenge.AttributeAttestationDescriptor>?): List<Primitive>? {
        if (requestedAttributes.isNullOrEmpty()) {
            if (otherAttributesEncoded != null) throw IllegalArgumentException("Unexpected Attributes found!")
            return null
        }
        return requireNotNull(otherAttributesEncoded) { "Requested attributes not found" }.decodeAs {
            requestedAttributes.mapIndexed { i, beAttestedAttribute ->
                val encoded = next().asExplicitlyTagged().verifyTag(i.toULong()).single().asPrimitive()
                beAttestedAttribute.type.asn1Decoder(encoded).also {
                    if (beAttestedAttribute.required && it == null) throw IllegalArgumentException("Attribute $i (${beAttestedAttribute.type.name}) is required but not present")
                }
            }
        }
    }

}

/** Decodes these values using the ordered attribute description carried by [challenge]. */
fun AttestedAttributes.parsedAttributesBy(challenge: AttestationChallenge) =
    parsedAttributesBy(challenge.toBeAttestedAttributes?.attributes)

/** Encodes only the additional attribute values, tagged by position, for storage in the TBS CSR. */
fun List<Primitive>.toSequence() = Asn1.Sequence {
    forEachIndexed { index, value ->
        +ExplicitlyTagged(index.toULong()) {
            +value.type.asn1Encoder(value)
        }
    }
}
