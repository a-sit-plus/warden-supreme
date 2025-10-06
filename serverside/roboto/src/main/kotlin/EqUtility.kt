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
    is Collection<*> -> {
        if (other !is Collection<*>) false
        else {
            if (size != other.size) false
            else {
                val self = toList()
                val other = other.toList()
                self.indices.firstOrNull { !self[it].contentEqualsIfArray(other[it]) }?.let { return false }
            }
        }
        true
    }

    else -> (this == other)
}

@Suppress("NOTHING_TO_INLINE")
inline fun Any.contentHashCodeIfArray() = when (this) {
    is Array<*> -> this.contentHashCode()
    is ByteArray -> this.contentHashCode()
    is ShortArray -> this.contentHashCode()
    is IntArray -> this.contentHashCode()
    is LongArray -> this.contentHashCode()
    is FloatArray -> this.contentHashCode()
    is DoubleArray -> this.contentHashCode()
    is CharArray -> this.contentHashCode()
    is BooleanArray -> this.contentHashCode()
    else -> this.hashCode()
}
