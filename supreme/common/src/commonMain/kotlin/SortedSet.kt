package at.asitplus.attestation.supreme

/** A KMP-compatible immutable set backed by sorted values, never by attacker-controlled hashes. */
class SortedSet<E>(
    values: Collection<E>,
    private val comparator: Comparator<E>,
    private val hash: (E) -> Int = { it.hashCode() },
) : Set<E> {
    private val canonicalValues = values.sortedWith(comparator).let { sorted ->
        sorted.filterIndexed { index, value ->
            index == 0 || comparator.compare(sorted[index - 1], value) != 0
        }
    }

    override val size get() = canonicalValues.size
    override fun isEmpty() = canonicalValues.isEmpty()
    override fun iterator() = canonicalValues.iterator()
    override fun contains(element: E) = canonicalValues.binarySearch { comparator.compare(it, element) } >= 0
    override fun containsAll(elements: Collection<E>) = elements.all(::contains)
    override fun equals(other: Any?): Boolean {
        if (other !is Set<*> || size != other.size) return false
        return try {
            @Suppress("UNCHECKED_CAST")
            containsAll(other as Set<E>)
        } catch (_: ClassCastException) {
            false
        }
    }

    override fun hashCode() = canonicalValues.fold(0) { result, value -> result + hash(value) }
}
