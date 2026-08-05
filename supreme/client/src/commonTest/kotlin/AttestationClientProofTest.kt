import at.asitplus.attestation.supreme.*
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.supreme.os.PlatformSigningProvider
import at.asitplus.test.Target
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.headersOf
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

private val clientTestInstant = Instant.parse("2025-01-10T00:00:00Z")
private val clientRequestedAttributes = AttestationChallenge.CertificationRequestAttributeAttestationDescriptor(
    ObjectIdentifier("1.3.6.1.4.1.60387.3"),
    listOf(
        AttestationChallenge.AttributeAttestationDescriptor("required", PrimitiveType.STRING),
        AttestationChallenge.AttributeAttestationDescriptor("optional", PrimitiveType.INT, required = false),
    ),
)

private fun clientChallenge(
    authentication: DataAuthentication,
    attributes: AttestationChallenge.CertificationRequestAttributeAttestationDescriptor? = null,
) = AttestationChallenge(
    issuedAt = clientTestInstant,
    validity = 1.hours,
    nonce = byteArrayOf(1, 2, 3, 4),
    attestationEndpoint = "https://example.invalid/attest",
    proofOID = WardenDefaults.OIDs.ATTESTATION_PROOF,
    genericDeviceNameOID = null,
    keyConstraints = WardenDefaults.KeyConstraints.p256Signer,
    attestableAttributes = attributes,
    dataAuth = authentication,
)

private fun clientFor(challenge: AttestationChallenge) = AttestationClient(
    HttpClient(MockEngine {
        respond(
            Json.encodeToString(challenge),
            headers = headersOf(HttpHeaders.ContentType, "application/json"),
        )
    }),
    object : Clock {
        override fun now() = clientTestInstant
    },
)

val AttestationClientProofTest by matrixSuite {
    if (Target.current == Target.ANDROID_ART) {
        test("attribute callback is called and signature auth creates a signed CSR") {
            val alias = "CLIENT_UNIT_SIGNATURE"
            PlatformSigningProvider.deleteSigningKey(alias)
            val challenge = clientChallenge(DataAuthentication.Signature, clientRequestedAttributes)
            var calls = 0

            val proof = challenge.createAttestationProof(alias) { requested ->
                calls++
                requested shouldBe clientRequestedAttributes.attributes
                listOf("present", null)
            }.getOrThrow()

            calls shouldBe 1
            proof.shouldBeInstanceOf<AttestationProof.Signed>()
        }

        test("attribute callback is called and hash auth creates an unsigned TBS CSR") {
            val alias = "CLIENT_UNIT_HASH"
            PlatformSigningProvider.deleteSigningKey(alias)
            val authentication = DataAuthentication.Hash(Digest.SHA256)
            val challenge = clientChallenge(authentication, clientRequestedAttributes)
            var calls = 0

            val proof = challenge.createAttestationProof(alias) { requested ->
                calls++
                requested shouldBe clientRequestedAttributes.attributes
                listOf("present", 42)
            }.getOrThrow()

            calls shouldBe 1
            proof.shouldBeInstanceOf<AttestationProof.Hashed>()
        }

        test("attribute callback is not called when no attributes are requested") {
            val alias = "CLIENT_UNIT_NO_ATTRIBUTES"
            PlatformSigningProvider.deleteSigningKey(alias)
            var calls = 0

            val proof = clientChallenge(
                DataAuthentication.Hash(Digest.SHA256)
            ).createAttestationProof(alias) {
                calls++
                emptyList()
            }.getOrThrow()

            calls shouldBe 0
            proof.shouldBeInstanceOf<AttestationProof.Hashed>()
        }
    }

    test("deprecated proof function rejects requested attributes") {
        @Suppress("DEPRECATION")
        val failure = clientChallenge(
            DataAuthentication.Signature,
            clientRequestedAttributes,
        ).createAttestationProof("UNUSED").exceptionOrNull()

        failure.shouldBeInstanceOf<IllegalArgumentException>().message shouldContain "cannot attest additional attributes"
    }

    test("deprecated proof function rejects hash authentication") {
        @Suppress("DEPRECATION")
        val failure = clientChallenge(
            DataAuthentication.Hash(Digest.SHA256)
        ).createAttestationProof("UNUSED").exceptionOrNull()

        failure.shouldBeInstanceOf<IllegalArgumentException>().message shouldContain "requires signature data authentication"
    }

    test("deprecated flow rejects requested attributes") {
        val challenge = clientChallenge(DataAuthentication.Signature, clientRequestedAttributes)

        @Suppress("DEPRECATION")
        val failure = catchingUnwrapped {
            clientFor(challenge).performAttestationFlow("UNUSED", io.ktor.http.Url("https://example.invalid/challenge"))
        }.exceptionOrNull()

        failure.shouldBeInstanceOf<IllegalArgumentException>().message shouldContain "cannot attest additional attributes"
    }

    test("deprecated flow rejects hash authentication") {
        val challenge = clientChallenge(DataAuthentication.Hash(Digest.SHA256))

        @Suppress("DEPRECATION")
        val failure = catchingUnwrapped {
            clientFor(challenge).performAttestationFlow("UNUSED", io.ktor.http.Url("https://example.invalid/challenge"))
        }.exceptionOrNull()

        failure.shouldBeInstanceOf<IllegalArgumentException>().message shouldContain "requires signature data authentication"
    }

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

