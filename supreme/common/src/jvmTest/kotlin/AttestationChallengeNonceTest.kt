import at.asitplus.attestation.supreme.AttestationChallenge
import at.asitplus.attestation.supreme.DataAuthentication
import at.asitplus.attestation.supreme.PrimitiveType
import at.asitplus.attestation.supreme.WardenDefaults
import at.asitplus.signum.indispensable.Digest
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import kotlinx.serialization.json.Json
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

private val challengeJson = Json {
    encodeDefaults = true
}

private val requestedAttributes = AttestationChallenge.CertificationRequestAttributeAttestationDescriptor(
    WardenDefaults.OIDs.DEVICE_NAME,
    listOf(AttestationChallenge.AttributeAttestationDescriptor("value", PrimitiveType.STRING)),
)

private data class VersionCase(
    val name: String,
    val dataAuth: DataAuthentication,
    val requestedAttributes: AttestationChallenge.CertificationRequestAttributeAttestationDescriptor?,
    val expectedVersion: Int,
)

val AttestationChallengeNonceTest by matrixSuite {
    "nonce length accepts inclusive 4 to 128 byte boundary" {
        challengeWithNonce(ByteArray(4)).nonce.size shouldBe 4
        challengeWithNonce(ByteArray(128)).nonce.size shouldBe 128
    }

    "nonce length rejects values smaller than 4 bytes" {
        shouldThrow<IllegalArgumentException> { challengeWithNonce(ByteArray(3)) }.message shouldContain "at least 4 bytes"
    }

    "nonce length rejects values larger than 128 bytes" {
        shouldThrow<IllegalArgumentException> { challengeWithNonce(ByteArray(129)) }.message shouldContain "at most 128 bytes"
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

        shouldThrow<IllegalArgumentException> {
            challengeJson.decodeFromString(AttestationChallenge.serializer(), encodedWithShortNonce)
        }.message shouldContain "at least 4 bytes"
    }

    "new default fields stay absent for old clients" {
        val encoded = challengeJson.encodeToString(
            AttestationChallenge.serializer(),
            challengeWithNonce(ByteArray(4)),
        )

        encoded shouldNotContain "\"toBeAttestedAttributes\""
        encoded shouldNotContain "\"dataAuth\""
    }

    data(
        "version reflects requested features",
        listOf(
            VersionCase("signature without attributes", DataAuthentication.Signature, null, 2),
            VersionCase("signature with attributes", DataAuthentication.Signature, requestedAttributes, 3),
            VersionCase("hash without attributes", DataAuthentication.Hash(Digest.SHA256), null, 3),
            VersionCase("hash with attributes", DataAuthentication.Hash(Digest.SHA256), requestedAttributes, 3),
        ),
        nameFn = { _, case -> case.name },
    ) test { case ->
        challengeWithNonce(
            nonce = ByteArray(4),
            dataAuth = case.dataAuth,
            requestedAttributes = case.requestedAttributes,
        ).version shouldBe case.expectedVersion
    }
}

private fun challengeWithNonce(
    nonce: ByteArray,
    dataAuth: DataAuthentication = DataAuthentication.Signature,
    requestedAttributes: AttestationChallenge.CertificationRequestAttributeAttestationDescriptor? = null,
) = AttestationChallenge(
    issuedAt = Instant.fromEpochMilliseconds(0),
    validity = 5.seconds,
    timeZone = null,
    nonce = nonce,
    attestationEndpoint = "https://example.invalid/attest",
    proofOID = WardenDefaults.OIDs.ATTESTATION_PROOF,
    toBeAttestedAttributes = requestedAttributes,
    dataAuth = dataAuth,
)
