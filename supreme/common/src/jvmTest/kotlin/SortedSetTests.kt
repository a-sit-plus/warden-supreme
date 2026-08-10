package at.asitplus.attestation.supreme

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.bind
import io.kotest.property.arbitrary.int

val SortedSetTests by matrixSuite {
    property(
        "deduplicates colliding values without hash-table insertion",
        Arb.bind(Arb.int(-1_000, 1_000), Arb.int(-1_000, 1_000), Arb.int(-1_000, 1_000)) { a, b, c ->
            listOf(CollidingValue(a), CollidingValue(b), CollidingValue(c), CollidingValue(a))
        },
        iterations = 256,
    ) test { values ->
        val actual = SortedSet(values, compareBy(CollidingValue::value))
        val expected = values.toHashSet()

        actual.containsAll(expected) shouldBe true
        expected.containsAll(actual) shouldBe true
    }
}

private class CollidingValue(val value: Int) {
    override fun equals(other: Any?) = other is CollidingValue && value == other.value
    override fun hashCode() = 0
}
