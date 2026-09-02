package at.asitplus.attestation.generator

import at.asitplus.attestation.android.AuthorizationList
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1ExplicitlyTagged
import at.asitplus.signum.indispensable.asn1.encoding.parse

/**
 * Returns a copy in which every occurrence of [property] is replaced by [rawExplicitProperty].
 *
 * [rawExplicitProperty] must be the complete explicitly-tagged ASN.1 property, including its
 * context-specific tag. Supplying it as raw ASN.1 intentionally permits malformed inner values;
 * this is for negative-test vectors, not normal construction.
 */
fun AuthorizationList.mangle(
    property: AuthorizationList.Tagged,
    rawExplicitProperty: Asn1Element,
): AuthorizationList = mangle(property.explicitTag, rawExplicitProperty)

/** Raw-tag variant for data-driven test vector tooling. */
fun AuthorizationList.mangle(
    propertyTag: ULong,
    rawExplicitProperty: Asn1Element,
): AuthorizationList {
    require(rawExplicitProperty is Asn1ExplicitlyTagged && rawExplicitProperty.tag.tagValue == propertyTag) {
        "Replacement must be an explicit [$propertyTag] authorization-list property"
    }
    return AuthorizationList.fromElements(
        elements.filterNot { it.hasTag(propertyTag) } + AuthorizationList.Element.Unknown(rawExplicitProperty)
    )
}

/** Convenience overload for hexadecimal DER containing the complete explicitly-tagged property. */
@OptIn(ExperimentalStdlibApi::class)
fun AuthorizationList.mangle(property: AuthorizationList.Tagged, rawExplicitPropertyDerHex: String): AuthorizationList =
    mangle(property, Asn1Element.parse(rawExplicitPropertyDerHex.hexToByteArray()))

/** Hex-DER convenience overload for data-driven test vector tooling. */
@OptIn(ExperimentalStdlibApi::class)
fun AuthorizationList.mangle(propertyTag: ULong, rawExplicitPropertyDerHex: String): AuthorizationList =
    mangle(propertyTag, Asn1Element.parse(rawExplicitPropertyDerHex.hexToByteArray()))

private fun AuthorizationList.Element.hasTag(propertyTag: ULong): Boolean = when (this) {
    is AuthorizationList.Element.Single -> value.tagged.explicitTag == propertyTag
    is AuthorizationList.Element.SetOf -> value.firstOrNull()?.tagged?.explicitTag == propertyTag
    is AuthorizationList.Element.Unknown ->
        (value as? Asn1ExplicitlyTagged)?.tag?.tagValue == propertyTag
}
