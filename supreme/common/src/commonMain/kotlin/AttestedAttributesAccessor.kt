package at.asitplus.attestation.supreme

/**
 * Returns the client-provided attributes requested by [challenge], parsed and keyed by their configured names.
 * Optional absent values are present in the map with a `null` value. If the challenge requested no attributes, the
 * map is empty.
 *
 * This property is intended for verifier callbacks, where the validated [AttestationChallenge] is already the receiver.
 * Access it only after generic verification has succeeded; malformed or missing values throw an exception.
 */
context(challenge: AttestationChallenge)
val AttestationProof.attestedAttributes: Map<String, Primitive>
    get() {
        val requested = challenge.toBeAttestedAttributes ?: return emptyMap()
        require(requested.attributes.map { it.name }.distinct().size == requested.attributes.size) {
            "Attested attribute names must be distinct"
        }
        val encoded = tbsCsr.attributes.single { it.oid == requested.oid }.value.single().asSequence()
        val values = requireNotNull(AttestedAttributes(encoded).parsedAttributesBy(requested.attributes))
        return requested.attributes.mapIndexed { index, attribute -> attribute.name to values[index] }.toMap()
    }
