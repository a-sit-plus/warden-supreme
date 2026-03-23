package at.asitplus.attestation.android

infix fun Any?.contentEqualsIfArray(other: Any?): Boolean = when (this) {
    null -> other == null
    is Array<*> -> (other is Array<*>) && this.contentEquals(other)
    is ByteArray -> (other is ByteArray) && this.contentEquals(other)
    is ShortArray -> (other is ShortArray) && this.contentEquals(other)
    is IntArray -> (other is IntArray) && this.contentEquals(other)
    is LongArray -> (other is LongArray) && this.contentEquals(other)
    is FloatArray -> (other is FloatArray) && this.contentEquals(other)
    is DoubleArray -> (other is DoubleArray) && this.contentEquals(other)
    is CharArray -> (other is CharArray) && this.contentEquals(other)
    is BooleanArray -> (other is BooleanArray) && this.contentEquals(other)
    is Collection<*> -> (other is Collection<*>) && this.contentEqualsCollection(other)

    else -> (this == other)
}

fun Any.contentHashCodeIfArray() = when (this) {
    is Array<*> -> this.contentHashCode()
    is ByteArray -> this.contentHashCode()
    is ShortArray -> this.contentHashCode()
    is IntArray -> this.contentHashCode()
    is LongArray -> this.contentHashCode()
    is FloatArray -> this.contentHashCode()
    is DoubleArray -> this.contentHashCode()
    is CharArray -> this.contentHashCode()
    is BooleanArray -> this.contentHashCode()
    is Collection<*> -> this.contentHashCodeCollection()
    else -> this.hashCode()
}

private fun Collection<*>.contentEqualsCollection(other: Collection<*>): Boolean {
    if (size != other.size) return false

    return if (this is Set<*> && other is Set<*>) {
        val unmatched = other.toMutableList()
        for (element in this) {
            val index = unmatched.indexOfFirst { candidate -> element.contentEqualsIfArray(candidate) }
            if (index < 0) return false
            unmatched.removeAt(index)
        }
        unmatched.isEmpty()
    } else {
        val self = toList()
        val otherValues = other.toList()
        self.indices.none { !self[it].contentEqualsIfArray(otherValues[it]) }
    }
}

private fun Collection<*>.contentHashCodeCollection(): Int =
    if (this is Set<*>) {
        fold(0) { acc, element -> acc + (element?.contentHashCodeIfArray() ?: 0) }
    } else {
        fold(1) { acc, element -> 31 * acc + (element?.contentHashCodeIfArray() ?: 0) }
    }
