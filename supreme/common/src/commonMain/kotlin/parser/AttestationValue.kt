package at.asitplus.attestation.android

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Exception
import at.asitplus.signum.indispensable.asn1.encoding.parse
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.InvocationKind
import kotlin.contracts.contract

/**
 * Either type containing:
 * * **on success:** the parsed [Success.value] with semantics attached
 * * **on failure:** the [Failure.rawAsn1Value], which is a deep copy of the non-parsable source element
 *
 * @param A the type of the parsed [Asn1Encodable]
 *
 * @see Asn1Element
 *
 */
//construction is contained to very few lines with generic code in AuthorizationList
//TODO add some intermediate type hierarchy foo to Tagged and encodable s.t. the tagged null decoding foo and all the construction that should go here don't need passing of Tagged at all!
sealed class AttestationValue<out A : Asn1Encodable<*>>() :
    AuthorizationList.Tagged.WithTag<Asn1Element>, PrettyPrintable {

    data class Success<out T : Asn1Encodable<*>> internal constructor(val value: T, override val tagged: AuthorizationList.Tagged) :
        AttestationValue<T>() {
        override fun encodeToTlv(): Asn1Element = value.encodeToTlv()
        override fun toString(): String {
            return "Success(" +
                    "value = $value" +
                    ")"
        }

        override fun doPrettyPrint(indent: String): String {
            return when (val v = value) {
                is PrettyPrintable -> v.doPrettyPrint(indent)
                else -> v.toString().prependIndent(indent)
            }
        }


    }

    class Failure<E : Asn1Element> internal constructor(
        val elementName: String,
        override val tagged: AuthorizationList.Tagged,
        source: E
    ) : AttestationValue<Asn1Encodable<*>>() {
        //make a copy of the offender
        val rawAsn1Value = Asn1Element.parse(source.derEncoded)
        override fun encodeToTlv(): Asn1Element = rawAsn1Value
        override fun toString(): String {
            return "Failure(" +
                    "elementName='$elementName', " +
                    "rawAsn1Value=${rawAsn1Value.toDerHexString()}" +
                    ")"
        }

        override fun doPrettyPrint(indent: String): String = buildString {
            append(indent).append("Failure(\n")
            append(indent).append("  elementName = '").append(elementName).append("'\n")
            append(indent).append("  rawAsn1Value = ").append(rawAsn1Value.toDerHexString()).append('\n')
            append(indent).append(")")
        }

         override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Failure<*>) return false

            if (elementName != other.elementName) return false
            if (tagged != other.tagged) return false
            if (!rawAsn1Value.derEncoded.contentEquals(other.rawAsn1Value.derEncoded)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = elementName.hashCode()
            result = 31 * result + tagged.hashCode()
            result = 31 * result + rawAsn1Value.derEncoded.contentHashCode()
            return result
        }

        /**
         * Converts the current object into an [AttestationValueException] with a detailed error message.
         * The generated exception includes information such as the element name, explicit tag,
         * and the raw ASN.1 value in DER-encoded hexadecimal format.
         *
         * @return An [AttestationValueException] with a descriptive message providing debugging details
         *         related to the ASN.1 element and its context.
         */
        fun toException() = AttestationValueException(elementName, tagged, rawAsn1Value)
    }

    /**
     * Runs [onSuccess] for [Success] or [onFailure] for [Failure].
     *
     * Note: this function rethrows any [Throwable] exception thrown by [onSuccess] or by [onFailure] function.
     *
     * @param onSuccess `(A) -> R` called with [Success.value].
     * @param onFailure `(String, AuthorizationList.Tagged, Asn1Element) -> R` called with
     *   [Failure.elementName], [tagged], and [Failure.rawAsn1Value].
     * @return `R` from [onSuccess] or [onFailure].
     */
    @OptIn(ExperimentalContracts::class)
    inline fun <R> fold(
        onSuccess: (A) -> R,
        onFailure: (String, AuthorizationList.Tagged, Asn1Element) -> R
    ): R {
        contract {
            callsInPlace(onSuccess, InvocationKind.AT_MOST_ONCE)
            callsInPlace(onFailure, InvocationKind.AT_MOST_ONCE)
        }

        return when (this) {
            is Success -> onSuccess(value)
            is Failure<*> -> onFailure(elementName, tagged, rawAsn1Value)
        }
    }

    @Deprecated("To be removed in 1.1. Do not use!", level = DeprecationLevel.ERROR)
    inline fun <R> onSuccess(onSuccess: (A) -> R): R? =
        if (this is Success) onSuccess(value) else {
            null
        }

    @Deprecated("To be removed in 1.1. Do not use!", level = DeprecationLevel.ERROR)
    inline fun <R> onFailure(onFailure: (String, AuthorizationList.Tagged, Asn1Element) -> R): R? =
        if (this is Failure<*>) onFailure(elementName, tagged, rawAsn1Value) else {
            null
        }

    fun isSuccess(): Boolean {
        @OptIn(ExperimentalContracts::class)
        contract { returns(true) implies (this@AttestationValue is Success<*>) }
        return this is Success
    }


    fun isFailure(): Boolean {
        @OptIn(ExperimentalContracts::class)
        contract { returns(true) implies (this@AttestationValue is Failure<*>) }
        return this is Failure<*>
    }

    @Deprecated(
        "Misnomer to be removed with 1.1",
        replaceWith = ReplaceWith("getOrThrow()"),
        level = DeprecationLevel.ERROR
    )
    @Throws(NoSuchElementException::class)
    inline fun get(): A = //  TODO TODO
        when (this) {
            is Success -> value
            is Failure<*> -> throw NoSuchElementException("No value present; elementName=$elementName, tagged=$tagged, rawAsn1Value=$rawAsn1Value")
        }

    /**
     * Returns the encapsulated value if this instance is of type [Success],
     * otherwise throws a `NoSuchElementException` with details from [Failure].
     *
     * @return the value of type `A` encapsulated in the `Success` instance.
     * @throws NoSuchElementException if this instance is of type `Failure`.
     */
    @Throws(NoSuchElementException::class)
    fun getOrThrow(): A = when (this) {
        is Success -> value
        is Failure<*> -> throw toException()
    }

    /**
     * Retrieves the encapsulated value if this instance is of type [Success], or `null`
     * otherwise.
     *
     * @return the encapsulated value of type `A` if this instance is `Success`,
     * or `null` if this instance is not `Success`.
     */
    fun getOrNull(): A? = when (this) {
        is Success -> value
        else -> null
    }

    /**
     * Returns the current instance as a [Failure] if it represents a failure state.
     * If the instance is not a failure, `null` is returned.
     *
     * @return the instance cast as a [Failure] if it represents a failure, or `null` otherwise.
     */
    fun failureOrNull(): Failure<*>? = if (isFailure()) this else null

    /**
     * Converts this instance to a [Result] object wrapping the success value or failure exception,
     * depending on the instance state.
     *
     * If this instance represents a success state, the encapsulated value is returned as a successful [Result].
     * If this instance represents a failure state, an [AttestationValueException] containing failure details
     * is returned as a failed [Result].
     *
     * @return a [Result] that is either successful with the encapsulated value or failed with an
     *         [AttestationValueException].
     */
    fun toResult(): Result<A> = fold(
        onSuccess = { Result.success(it) },
        onFailure = { elementName, tagged, source ->
            Result.failure(
                AttestationValueException(
                    elementName,
                    tagged,
                    source
                )
            )
        })

    /** [KmmResult] version of [toResult]
     *
     * @see toResult
     */
    fun toKmmResult(): KmmResult<A> = toResult().wrap()
}

/**
 * Exception equivalent of [AttestationValue.Failure]
 */
class AttestationValueException(
    val elementName: String,
    val tagged: AuthorizationList.Tagged,
    val source: Asn1Element
) : Asn1Exception("No value present; elementName=$elementName, explicit tag=${tagged.explicitTag}, rawAsn1Value=${source.toDerHexString()}") {
    fun toFailure() = AttestationValue.Failure(elementName, tagged, source)
}
