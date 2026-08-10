@file:OptIn(io.kotest.common.ExperimentalKotest::class)

package at.asitplus.attestation.android.engine

import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.PropTestConfig
import io.kotest.property.arbitrary.int
import io.kotest.property.checkAll
import kotlin.random.Random

private val selectorApp = AndroidAttestationConfiguration.AppData(
    packageName = "at.example.app",
    signerFingerprints = setOf(byteArrayOf(1, 2, 3, 4)),
)

val AttestedApplicationSelectorTests by matrixSuite {
    "selects the only configured application from a minimal valid KeyDescription" {
        selectAttestedApplication(validExtension(), listOf(selectorApp)) shouldBe selectorApp
    }

    data(
        "malformed selector input",
        listOf(
            "extension exceeds size ceiling" to ByteArray(64 * 1024 + 1),
            "truncated high-tag identifier" to byteArrayOf(0xbf.toByte()),
            "truncated long-form length" to byteArrayOf(4, 0x82.toByte(), 1),
            "multiple DER roots" to (octets(byteArrayOf()) + octets(byteArrayOf())),
            "application ID exceeds size ceiling" to extension(appId = ByteArray(32 * 1024 + 1)),
            "too many packages" to validExtension(packages = List(33) { "at.example.app" }),
            "too many digests" to validExtension(digests = List(65) { byteArrayOf(it.toByte()) }),
            "oversized package name" to validExtension(packages = listOf("x".repeat(256))),
            "oversized digest" to validExtension(digests = listOf(ByteArray(129))),
            "duplicate application ID tag" to extension(appIdTags = 2),
            "deeply nested application ID" to extension(appId = nestedSequence(65)),
            "deeply nested AuthorizationList value" to extension(extraAuthorizationListValue = nestedSequence(65)),
        ),
        nameFn = { _, (name, _) -> name },
    ) - { (_, der) ->
        "never selects an application" {
            shouldThrow<Throwable> { selectAttestedApplication(der, listOf(selectorApp)) }
        }
    }

    "property-style DER fuzzer fails closed for malformed input" {
        checkAll(PropTestConfig(iterations = 4_096), Arb.int()) { seed ->
            shouldThrow<Throwable> {
                selectAttestedApplication(malformedExtension(Random(seed)), listOf(selectorApp))
            }
        }
    }

    "property-style DER fuzzer preserves a valid application ID" {
        checkAll(PropTestConfig(iterations = 512), Arb.int(0, 19)) { depth ->
            selectAttestedApplication(
                extension(extraAuthorizationListValue = nestedSequence(depth)),
                listOf(selectorApp),
            ) shouldBe selectorApp
        }
    }
}

private fun malformedExtension(random: Random): ByteArray = when (random.nextInt(5)) {
    0 -> byteArrayOf(4, 0x84.toByte(), -1, -1, -1, -1)
    1 -> byteArrayOf(0x1f, 0x80.toByte())
    2 -> validExtension() + random.nextBytes(random.nextInt(1, 256))
    3 -> extension(appId = nestedSequence(random.nextInt(65, 128)))
    else -> extension(extraAuthorizationListValue = nestedSequence(random.nextInt(65, 128)))
}

private fun validExtension(
    packages: List<String> = listOf(selectorApp.packageName),
    digests: List<ByteArray> = selectorApp.signerFingerprints.toList(),
) = extension(appId = applicationId(packages, digests))

private fun extension(
    appId: ByteArray = applicationId(),
    appIdTags: Int = 1,
    extraAuthorizationListValue: ByteArray? = null,
): ByteArray {
    val authorizationList = buildList {
        repeat(appIdTags) { add(explicitTag(709, octets(appId))) }
        extraAuthorizationListValue?.let(::add)
    }
    val keyDescription = sequence(
        integer(1), integer(1), integer(1), integer(1), octets(byteArrayOf()), octets(byteArrayOf()),
        sequence(*authorizationList.toTypedArray()), sequence(),
    )
    return octets(keyDescription)
}

private fun applicationId(
    packages: List<String> = listOf(selectorApp.packageName),
    digests: List<ByteArray> = selectorApp.signerFingerprints.toList(),
) = sequence(
    set(*packages.map { sequence(octets(it.encodeToByteArray()), integer(1)) }.toTypedArray()),
    set(*digests.map(::octets).toTypedArray()),
)

private fun nestedSequence(depth: Int): ByteArray {
    var value = byteArrayOf(5, 0)
    repeat(depth) { value = sequence(value) }
    return value
}

private fun integer(value: Int) = der(2, byteArrayOf(value.toByte()))
private fun octets(value: ByteArray) = der(4, value)
private fun sequence(vararg values: ByteArray) = der(0x30, values.concat())
private fun set(vararg values: ByteArray) = der(0x31, values.concat())
private fun explicitTag(number: Int, value: ByteArray): ByteArray {
    require(number == 709)
    return der(byteArrayOf(0xbf.toByte(), 0x85.toByte(), 0x45), value)
}

private fun der(tag: Int, value: ByteArray) = der(byteArrayOf(tag.toByte()), value)
private fun der(tag: ByteArray, value: ByteArray) = tag + length(value.size) + value
private fun length(value: Int) = when {
    value < 128 -> byteArrayOf(value.toByte())
    value <= 0xff -> byteArrayOf(0x81.toByte(), value.toByte())
    else -> byteArrayOf(0x82.toByte(), (value shr 8).toByte(), value.toByte())
}
private fun Array<out ByteArray>.concat() = fold(ByteArray(0)) { result, value -> result + value }
