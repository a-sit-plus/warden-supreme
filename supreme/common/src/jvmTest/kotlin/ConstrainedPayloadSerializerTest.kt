import at.asitplus.attestation.supreme.AttestationChallenge
import at.asitplus.attestation.supreme.Constrained
import at.asitplus.attestation.supreme.WardenDefaults
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json

private val json = Json {
    encodeDefaults = true
}

val ConstrainedPayloadSerializerTest by matrixSuite {
    "precise primitives + nested map roundtrip" {
        val challenge = AttestationChallenge(
            issuedAt = Instant.fromEpochMilliseconds(0),
            validity = 5.seconds,
            timeZone = null,
            nonce = byteArrayOf(0x01, 0x02, 0x03, 0x04),
            attestationEndpoint = "https://example.invalid/attest",
            proofOID = WardenDefaults.OIDs.ATTESTATION_PROOF,
            additionalPayload = mapOf(
                "nullableString" to (null as Constrained),
                "nullableInt" to (null as Constrained),
                "aBool" to true,
                "aString" to "hello",
                "aByte" to 0x7f.toByte(),
                "aShort" to 32000.toShort(),
                "anInt" to 123,
                "aLong" to 123L,
                "aChar" to 'x',
                "aFloat" to 1.5f,
                "aDouble" to 2.5,
                "nested" to mapOf("inner" to 1) as Constrained,
                "anotherNull" to (null as Constrained),
            ),
        )

        val encoded = json.encodeToString(AttestationChallenge.serializer(), challenge)
        val decoded = json.decodeFromString(AttestationChallenge.serializer(), encoded)
        val payload = decoded.additionalPayload.shouldNotBeNull()

        payload["nullableString"] shouldBe null
        payload["nullableInt"] shouldBe null
        payload["nullableViaReified"] shouldBe null
        payload["aByte"].shouldBeInstanceOf<Byte>()
        payload["aShort"].shouldBeInstanceOf<Short>()
        payload["anInt"].shouldBeInstanceOf<Int>()
        payload["aLong"].shouldBeInstanceOf<Long>()
        payload["aChar"].shouldBeInstanceOf<Char>()
        payload["aFloat"].shouldBeInstanceOf<Float>()
        payload["aDouble"].shouldBeInstanceOf<Double>()

        val nested = (payload["nested"] as? Map<*, *>).shouldNotBeNull()
        nested["inner"] shouldBe 1
    }

    "missing value decodes as default (simulates default-eliding formats)" {
        val challenge = AttestationChallenge(
            issuedAt = Instant.fromEpochMilliseconds(0),
            validity = 5.seconds,
            timeZone = null,
            nonce = byteArrayOf(0x01, 0x02, 0x03, 0x04),
            attestationEndpoint = "https://example.invalid/attest",
            proofOID = WardenDefaults.OIDs.ATTESTATION_PROOF,
            additionalPayload = mapOf("zero" to 0),
        )
        val encoded = json.encodeToString(AttestationChallenge.serializer(), challenge)
        val withoutValue = encoded.replace("\"value\":0,", "").replace(",\"value\":0", "")
        val decoded = json.decodeFromString(AttestationChallenge.serializer(), withoutValue)
        val payload = decoded.additionalPayload.shouldNotBeNull()
        payload["zero"] shouldBe 0
    }

    "unsupported values fail at runtime" {
        val challenge = AttestationChallenge(
            issuedAt = Instant.fromEpochMilliseconds(0),
            validity = 5.seconds,
            timeZone = null,
            nonce = byteArrayOf(0x01, 0x02, 0x03, 0x04),
            attestationEndpoint = "https://example.invalid/attest",
            proofOID = WardenDefaults.OIDs.ATTESTATION_PROOF,
            additionalPayload = mapOf(
                "bad" to ({ 42 } as Constrained),
            ),
        )

        val error = runCatching {
            json.encodeToString(AttestationChallenge.serializer(), challenge)
        }.exceptionOrNull()
        error.shouldBeInstanceOf<SerializationException>()
    }
}
