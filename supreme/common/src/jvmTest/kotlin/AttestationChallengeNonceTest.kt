import at.asitplus.attestation.supreme.AttestationChallenge
import at.asitplus.attestation.supreme.DataAuthentication
import at.asitplus.attestation.supreme.KeyConstraints
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.misc.BitLength
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import at.asitplus.attestation.supreme.PrimitiveType
import at.asitplus.attestation.supreme.WardenDefaults
import at.asitplus.attestation.supreme.requireBoundedArrayNesting
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import kotlinx.serialization.SerializationException
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

    "nesting guard ignores delimiters in strings" {
        requireBoundedArrayNesting("""{"value":"[{]} \" [}"}""")
        shouldThrow<SerializationException> { requireBoundedArrayNesting("[}") }
    }

    data(
        "version reflects requested features",
        listOf(
            VersionCase("signature without attributes", DataAuthentication.Signature, null, 2),
            VersionCase("signature with attributes", DataAuthentication.Signature, requestedAttributes, AttestationChallenge.CURRENT_VERSION),
            VersionCase("hash without attributes", DataAuthentication.Hash(Digest.SHA256), null, AttestationChallenge.CURRENT_VERSION),
            VersionCase("hash with attributes", DataAuthentication.Hash(Digest.SHA256), requestedAttributes, AttestationChallenge.CURRENT_VERSION),
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

private data class WireVersionCase(
    val name: String,
    val dataAuth: DataAuthentication,
    val keyConstraints: KeyConstraints?,
    val inMemoryVersion: Int,
    val wireVersion: Int,
)

private val ec = KeyConstraints(KeyConstraints.AlgorithmParameters.EC(ECCurve.SECP_384_R_1))
private val rsa = KeyConstraints(KeyConstraints.AlgorithmParameters.RSA(BitLength(3072u)))
private val mlDsa = WardenDefaults.KeyConstraints.mlDsa65Signer
private val hash = DataAuthentication.Hash(Digest.SHA256)

val AttestationChallengeWireVersionTest by matrixSuite {
    test("version 4 is the first after the pre-ML-DSA version") {
        AttestationChallenge.CURRENT_VERSION shouldBe 4
        AttestationChallenge.WireSerializer.PRE_ML_DSA_VERSION shouldBe 3
    }

    data(
        "wire version",
        listOf(
            WireVersionCase("signature, no key constraints", DataAuthentication.Signature, null, 2, 2),
            WireVersionCase("signature, EC", DataAuthentication.Signature, ec, 2, 2),
            WireVersionCase("signature, RSA", DataAuthentication.Signature, rsa, 2, 2),
            WireVersionCase("signature, ML-DSA", DataAuthentication.Signature, mlDsa, 4, 4),
            WireVersionCase("hash, no key constraints", hash, null, 4, 3),
            WireVersionCase("hash, EC", hash, ec, 4, 3),
            WireVersionCase("hash, RSA", hash, rsa, 4, 3),
            WireVersionCase("hash, ML-DSA", hash, mlDsa, 4, 4),
        ),
        nameFn = { _, case -> case.name },
    ) test { case ->
        val challenge = AttestationChallenge(
            issuedAt = Instant.fromEpochMilliseconds(0),
            validity = 5.seconds,
            nonce = ByteArray(8),
            attestationEndpoint = "https://example.invalid/attest",
            proofOID = WardenDefaults.OIDs.ATTESTATION_PROOF,
            keyConstraints = case.keyConstraints,
            dataAuth = case.dataAuth,
        )
        challenge.version shouldBe case.inMemoryVersion

        val json = Json.encodeToString(AttestationChallenge.serializer(), challenge)
        Json.parseToJsonElement(json).jsonObject["version"]!!.jsonPrimitive.int shouldBe case.wireVersion
        // decoding yields the wire version; everything else is unchanged
        val decoded = Json.decodeFromString(AttestationChallenge.serializer(), json)
        decoded.version shouldBe case.wireVersion
        decoded.keyConstraints shouldBe challenge.keyConstraints
        decoded.dataAuth shouldBe challenge.dataAuth
        decoded.nonce.contentEquals(challenge.nonce) shouldBe true
        // pre-ML-DSA clients accept any challenge whose wire version is at most 3, i.e. all but ML-DSA ones
        (case.wireVersion <= AttestationChallenge.WireSerializer.PRE_ML_DSA_VERSION) shouldBe
                (case.keyConstraints != mlDsa)
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
