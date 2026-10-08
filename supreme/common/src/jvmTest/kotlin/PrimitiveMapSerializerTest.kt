@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)

import at.asitplus.attestation.supreme.*
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.json.*

@Serializable
private data class BinaryPrimitive(val type: PrimitiveType, val value: ByteArray)

private fun assertPrimitiveMaps(expected: Map<String, Primitive>, actual: Map<String, Primitive>) {
    actual.keys shouldBe expected.keys
    expected.forEach { (key, value) ->
        val decoded = actual.getValue(key)
        decoded?.let { it::class } shouldBe value?.let { it::class }
        if (value is ByteArray) (decoded as ByteArray).contentEquals(value) shouldBe true
        else decoded shouldBe value
    }
}

val PrimitiveMapSerializerTest by matrixSuite {
    val values = mapOf<String, Primitive>(
        "null" to null, "boolean" to true, "string" to "hello",
        "byte" to Byte.MIN_VALUE, "short" to Short.MAX_VALUE, "int" to Int.MIN_VALUE,
        "long" to Long.MAX_VALUE, "char" to 'x', "float" to 1.25f, "double" to -2.5,
        "bytearray" to byteArrayOf(-128, 0, 127),
        "zero" to 0, "false" to false, "empty" to "", "emptyBytes" to byteArrayOf(),
    )
    val responses = listOf("Success", "Failure")
    fun newResponse(kind: String): AttestationResponse = when (kind) {
        "Success" -> AttestationResponse.Success(emptyList())
        else -> AttestationResponse.Failure(AttestationResponse.Failure.Type.CONTENT, "invalid")
    }

    "response info round-trips plain primitives through JSON and binary ASN.1 payloads" - {
        data("responses", responses) - { kind ->
            data("formats", listOf("JSON", "CBOR")) test { format ->
                val response = newResponse(kind)
                response.info.putAll(values)
                val decoded = when (format) {
                    "JSON" -> {
                        val encoded = Json.encodeToString(response)
                        val info = Json.parseToJsonElement(encoded).jsonObject.getValue("info").jsonObject
                        info.getValue("int").jsonObject shouldBe buildJsonObject {
                            put("type", "int")
                            put("value", Int.MIN_VALUE)
                        }
                        Json.decodeFromString(AttestationResponse.serializer(), encoded)
                    }
                    else -> Cbor.decodeFromByteArray(
                        AttestationResponse.serializer(),
                        Cbor.encodeToByteArray(AttestationResponse.serializer(), response),
                    )
                }
                assertPrimitiveMaps(values, decoded.info)
                decoded.info["added"] = 42
                decoded.info["added"] shouldBe 42
            }
        }
    }

    "binary values use existing ASN.1 codecs and stable type IDs" - {
        data("primitives", values.entries, nameFn = { _, entry -> entry.key }) test { (_, value) ->
            val type = value.type
            val encoded = Cbor.encodeToByteArray(PrimitiveSerializer, value)
            val payload = Cbor.decodeFromByteArray(BinaryPrimitive.serializer(), encoded)
            payload.type shouldBe type
            payload.value.contentEquals(type.asn1Encoder(value).derEncoded) shouldBe true
            Cbor.encodeToByteArray(PrimitiveType.serializer(), type)
                .contentEquals(byteArrayOf(type.id.toByte())) shouldBe true
        }
    }

    "empty info stays omitted and missing info produces a mutable empty map" - {
        data("responses", responses) test { kind ->
            val json = Json { encodeDefaults = true }
            val empty = newResponse(kind)
            val encoded = json.encodeToString(AttestationResponse.serializer(), empty)
            json.parseToJsonElement(encoded).jsonObject.containsKey("info") shouldBe false
            val decoded = Json.decodeFromString(AttestationResponse.serializer(), encoded)
            decoded.info.isEmpty() shouldBe true
            decoded.info["count"] = 1
            decoded.info["count"] shouldBe 1
        }
    }

    "unsupported values and malformed JSON or ASN.1 are rejected" - {
        data("unsupported values", listOf("JSON", "CBOR")) test { format ->
            shouldThrow<SerializationException> {
                when (format) {
                    "JSON" -> Json.encodeToString(PrimitiveSerializer, listOf(1))
                    else -> Cbor.encodeToByteArray(PrimitiveSerializer, listOf(1))
                }
            }
        }
        data("malformed JSON", listOf(
            """{"type":"unknown","value":1}""",
            """{"type":"null","value":1}""",
            """{"type":"byte","value":128}""",
            """{"type":"char","value":"ab"}""",
        )) test { encoded ->
            shouldThrow<SerializationException> { Json.decodeFromString(PrimitiveSerializer, encoded) }
        }
        data("malformed ASN.1", listOf(
            "empty DER" to BinaryPrimitive(PrimitiveType.INT, byteArrayOf()),
            "wrong ASN.1 type" to BinaryPrimitive(PrimitiveType.NULL, PrimitiveType.INT.asn1Encoder(42).derEncoded),
        ), nameFn = { _, case -> case.first }) test { (_, payload) ->
            shouldThrow<SerializationException> {
                Cbor.decodeFromByteArray(PrimitiveSerializer, Cbor.encodeToByteArray(BinaryPrimitive.serializer(), payload))
            }
        }
    }
}
