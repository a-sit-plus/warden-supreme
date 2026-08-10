import at.asitplus.attestation.supreme.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.headersOf
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

private val clientTestInstant = Instant.parse("2025-01-10T00:00:00Z")



private fun clientForJson(
    json: String,
    maxAttestationPayloadBytes: Int = WardenDefaults.DEFAULT_MAX_ATTESTATION_PAYLOAD_BYTES,
) = AttestationClient(
    HttpClient(MockEngine {
        respond(json, headers = headersOf(HttpHeaders.ContentType, "application/json"))
    }),
    object : Clock {
        override fun now() = clientTestInstant
    },
    maxAttestationPayloadBytes,
)

val AttestationClientProofTest by matrixSuite {
    test("challenge rejects excessive payload size") {
        clientForJson("{}", maxAttestationPayloadBytes = 1)
            .getChallenge(io.ktor.http.Url("https://example.invalid/challenge"))
            .exceptionOrNull()
            .shouldBeInstanceOf<IllegalArgumentException>()
            .message shouldBe "Attestation payload exceeds 1 bytes"
    }

    test("challenge rejects excessive nested payload") {
        val nestedPayload = buildString {
            append("{\"k\":")
            repeat(MAX_JSON_NESTING_DEPTH) { append("{\"type\":11,\"value\":{\"k\":") }
            append("{\"type\":6,\"value\":0}")
            repeat(MAX_JSON_NESTING_DEPTH) { append("}}") }
            append('}')
        }
        val challengeJson = Json.encodeToString(AttestationChallenge(
            issuedAt = clientTestInstant,
            validity = 5.seconds,
            nonce = ByteArray(4),
            attestationEndpoint = "https://example.invalid/attest",
            proofOID = WardenDefaults.OIDs.ATTESTATION_PROOF,
        ))
            .dropLast(1) + ",\"additionalPayload\":$nestedPayload}"

        clientForJson(challengeJson)
            .getChallenge(io.ktor.http.Url("https://example.invalid/challenge"))
            .exceptionOrNull()
            .shouldBeInstanceOf<SerializationException>()
    }
}
