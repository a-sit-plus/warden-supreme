package at.asitplus.attestation.android

import at.asitplus.signum.indispensable.asn1.Asn1CustomStructure
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Element.Tag
import at.asitplus.signum.indispensable.asn1.Asn1Set

internal fun Asn1Set.Companion.fromPresorted(children: List<Asn1Element>) = Asn1CustomStructure(
    tag = Tag.SET.tagValue.toUByte(),
    children = children,
    sortChildren = false,
    shouldBeSorted = true
)

internal operator fun String.times(int: Int) = repeat(int)