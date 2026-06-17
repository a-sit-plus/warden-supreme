import at.asitplus.attestation.supreme.AttestationChallenge
import at.asitplus.attestation.supreme.WardenDefaults
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.Json
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

private val challengeJson = Json {
    encodeDefaults = true
}

val AttestationChallengeNonceTest by matrixSuite {
    "nonce length accepts inclusive 4 to 128 byte boundary" {
        challengeWithNonce(ByteArray(4)).nonce.size shouldBe 4
        challengeWithNonce(ByteArray(128)).nonce.size shouldBe 128
    }

    "nonce length rejects values smaller than 4 bytes" {
        val failure = runCatching { challengeWithNonce(ByteArray(3)) }.exceptionOrNull()

        failure.shouldBeInstanceOf<IllegalArgumentException>()
        failure.message shouldContain "at least 4 bytes"
    }

    "nonce length rejects values larger than 128 bytes" {
        val failure = runCatching { challengeWithNonce(ByteArray(129)) }.exceptionOrNull()

        failure.shouldBeInstanceOf<IllegalArgumentException>()
        failure.message shouldContain "at most 128 bytes"
    }

    "nonce length is enforced when decoding wire data" {
        val encoded = challengeJson.encodeToString(
            AttestationChallenge.serializer(),
            challengeWithNonce(ByteArray(4))
        )
        val encodedWithShortNonce = encoded.replace(
            Regex("\"nonce\":\"[^\"]+\""),
            "\"nonce\":\"AQID\""
        )

        val failure = runCatching {
            challengeJson.decodeFromString(AttestationChallenge.serializer(), encodedWithShortNonce)
        }.exceptionOrNull()

        failure.shouldBeInstanceOf<IllegalArgumentException>()
        failure.message shouldContain "at least 4 bytes"
    }
}

private fun challengeWithNonce(nonce: ByteArray) = AttestationChallenge(
    issuedAt = Instant.fromEpochMilliseconds(0),
    validity = 5.seconds,
    timeZone = null,
    nonce = nonce,
    attestationEndpoint = "https://example.invalid/attest",
    proofOID = WardenDefaults.OIDs.ATTESTATION_PROOF,
)
