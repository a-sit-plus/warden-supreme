@file:OptIn(io.kotest.common.ExperimentalKotest::class)

package at.asitplus.attestation.android

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Set
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.*

val AttestationApplicationIdCanonicalizationTests by matrixSuite {
    property(
        "canonical application ID collections preserve hash-set membership",
        Arb.bind(
            Arb.byteArray(Arb.int(0, 64), Arb.byte()),
            Arb.string(0..32),
            Arb.int(0, Int.MAX_VALUE),
            Arb.int(0, 64),
            Arb.int(0, 64),
        ) { digest, packageName, version, packageCount, digestCount ->
            TestInput(digest, packageName, version, packageCount, digestCount)
        },
    ) test { (digest, packageName, version, packageCount, digestCount) ->
        val digests = List(digestCount) { index ->
            if (index % 3 == 0) digest.copyOf() else digest + index.toByte()
        }
        val packages = List(packageCount) { index ->
            AuthorizationList.AttestationPackageInfo(
                if (index % 3 == 0) packageName else "$packageName.$index",
                version.toUInt() + index.toUInt(),
            )
        }

        val actual = decodeApplicationId(packages, digests)
        val expectedPackages = packages.toHashSet()

        actual.packageInfos.containsAll(expectedPackages) shouldBe true
        expectedPackages.containsAll(actual.packageInfos) shouldBe true
        actual.signatureDigests.all { actualDigest -> digests.any { it.contentEquals(actualDigest) } } shouldBe true
        digests.map { it.toList() }.toHashSet().all { expectedDigest ->
            actual.signatureDigests.any { it.toList() == expectedDigest }
        } shouldBe true
    }
}

private data class TestInput(
    val digest: ByteArray,
    val packageName: String,
    val version: Int,
    val packageCount: Int,
    val digestCount: Int,
)

private fun decodeApplicationId(
    packages: List<AuthorizationList.AttestationPackageInfo>,
    digests: List<ByteArray>,
): AuthorizationList.AttestationApplicationId = AuthorizationList.AttestationApplicationId.decodeFromTlv(
    Asn1Element.parse(Asn1.OctetStringEncapsulating {
        +Asn1.Sequence {
            +Asn1Set.fromPresorted(packages.map { it.encodeToTlv() })
            +Asn1Set.fromPresorted(digests.map { Asn1.OctetString(it) })
        }
    }.derEncoded)
)
