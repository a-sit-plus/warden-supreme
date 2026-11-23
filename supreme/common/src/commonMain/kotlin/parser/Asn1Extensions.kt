package at.asitplus.attestation.android

import at.asitplus.awesn1.*
import at.asitplus.awesn1.Asn1Element.Tag

internal fun Asn1Set.Companion.fromPresorted(children: List<Asn1Element>) = Asn1CustomStructure(
    tag = Tag.SET.tagValue.toUByte(),
    children = children,
    sortChildren = false,
    shouldBeSorted = true
)

internal operator fun String.times(int: Int) = repeat(int)