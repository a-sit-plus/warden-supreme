package at.asitplus.attestation.android

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.encoding.parse
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.contract

/**
 * Either type containing:
 * * **on success:** the parsed [Success.value] with semantics attached
 * * **on failure:** the [Failure.rawAsn1Value], which is a deep copy of the non-parsable source element
 *
 * @param T the type of the parsed [Asn1Encodable]
 *
 * @see Asn1Element
 *
 */
//TODO move construction of AttestationValues here using a helper function, so the ghastly casts that are currently all over the place inside AuthorizationList go here.
//TODO no.2: add some intermediate type hierarchy foo to Tagged and encodable s.t. the tagged null decoding foo and all the construction that should go here don't need passing of Tagged at all!
sealed class AttestationValue<out A : Asn1Encodable<*>>(override val tagged: AuthorizationList.Tagged) :
    AuthorizationList.Tagged.WithTag<Asn1Element>, PrettyPrintable {

    class Success<out T : Asn1Encodable<*>> internal constructor(val value: T, tagged: AuthorizationList.Tagged) :
        AttestationValue<T>(tagged) {
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
        tagged: AuthorizationList.Tagged,
        source: E
    ) : AttestationValue<Asn1Encodable<*>>(tagged) {
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

    }

    inline fun fold(
        onSuccess: (A) -> Unit,
        onFailure: (String, AuthorizationList.Tagged, Asn1Element) -> Unit
    ) = when (this) {
        is Success -> onSuccess(value)
        is Failure<*> -> onFailure(elementName, tagged, rawAsn1Value)
    }

    inline fun <R> onSuccess(onSuccess: (A) -> R): R? =
        if (this is Success) onSuccess(value) else {
            null
        }

    inline fun <R> onFailure(onFailure: (String, AuthorizationList.Tagged, Asn1Element) -> R): R? =
        if (this is Failure<*>) onFailure(elementName, tagged, rawAsn1Value) else {
            null
        }

    fun isSuccess(): Boolean {
        @OptIn(ExperimentalContracts::class)
        contract { returns(true) implies (this@AttestationValue is Success<*>) }
        return this is Success
    }

    inline fun get(): A = //  TODO TODO
        when (this) {
            is Success -> value
            is Failure<*> -> throw NoSuchElementException("No value present; elementName=$elementName, tagged=$tagged, rawAsn1Value=$rawAsn1Value")
        }
}

internal inline fun <reified E : Asn1Element, reified T : Asn1Encodable<E>, reified A : AttestationValue<T>> E.parsing(
    tagged: AuthorizationList.Tagged,
    block: () -> T
): AttestationValue<T> = catchingUnwrapped {
    block.invoke()
}.fold(
    onSuccess = { AttestationValue.Success(it, tagged) },
    onFailure = { AttestationValue.Failure(E::class.simpleName!!, tagged, this) as AttestationValue<T> }
)
