@file:OptIn(kotlin.time.ExperimentalTime::class)

package at.asitplus.attestation.supreme

import at.asitplus.attestation.supreme.AttestationProof.Hashed
import at.asitplus.attestation.supreme.AttestationProof.Signed
import at.asitplus.signum.indispensable.pki.TbsCertificationRequest
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.toCryptoPublicKey
import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixConfig
import at.asitplus.testballoon.matrix.matrixSuite
import examples.javaapi.JavaAttestationVerifierTestApi.Harness
import examples.javaapi.JavaAttestationVerifierTestApi.RecordingCallbacks
import examples.javaapi.SupremeVerifierJavaApi
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import java.util.Base64
import java.util.Date
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.time.Duration

private data class JavaProofFixture(
    val challenge: AttestationChallenge,
    val proof: Signed,
    val certificateChain: List<X509Certificate>,
)

private fun AndroidFixture.javaHarness(
    packageName: String = fakeAndroidPackage,
): Harness = Harness(
    SupremeConfiguration(
        android = trustedConfig(packageName = packageName),
        clock = SupremeConfiguration.Clock.Fixed(fixedClock.now()),
        verificationTimeOffset = Duration.ZERO,
    ),
)

private fun AndroidFixture.issueJavaProof(harness: Harness): JavaProofFixture {
    val challenge = harness.issueChallenge(attestationEndpoint).get(10, TimeUnit.SECONDS)
    val attestation = createFakeAndroidAttestationWithRoots(
        challenge = challenge.nonce,
        packageName = fakeAndroidPackage,
        signatureDigest = fakeAndroidSignerDigest,
        creationTime = Date(fixedClock.now().toEpochMilliseconds()),
        deviceLocked = true,
        verifiedBootState = BootState.VERIFIED,
        rootKeyPair = fake.rootKeyPair,
        rootCertificate = fake.rootCertificate,
        intermediateKeyPair = fake.intermediateKeyPair,
        intermediateCertificate = fake.intermediateCertificate,
    )
    return JavaProofFixture(
        challenge = challenge,
        proof = Signed(createCsr(challenge, attestation.attestationJson(), attestation.leafKeyPair)),
        certificateChain = attestation.certificateChain.toSignumChain(),
    )
}

val SupremeVerifierJavaApiTest by matrixSuite(matrixConfig { execution = ExecutionMode.Sequential }) {

    val documentedVerifier = SupremeVerifierJavaApi.newVerifier()

    "documented challenge API" {
        val future = SupremeVerifierJavaApi.issueChallenge(documentedVerifier, "https://example.test/attest")
        future.shouldBeInstanceOf<CompletableFuture<AttestationChallenge>>()
        future.get(10, TimeUnit.SECONDS).attestationEndpoint shouldBe "https://example.test/attest"
    }

    "documented malformed proof API" {
        SupremeVerifierJavaApi.verify(
            documentedVerifier,
            Hashed(
                TbsCertificationRequest(
                    subjectName = emptyList(),
                    publicKey = generateRsaKeyPair(1024).public.toCryptoPublicKey().getOrThrow(),
                    attributes = emptyList(),
                ),
            ),
        ).get(10, TimeUnit.SECONDS)
            .shouldBeInstanceOf<AttestationResponse.Failure>()
            .kind shouldBe AttestationResponse.Failure.Type.CONTENT
    }

    fixture { generateAndroidFixture() } - {
        test("successful verification preserves every Java callback argument and order") { fixture ->
            val harness = fixture.javaHarness()
            val issued = fixture.issueJavaProof(harness)
            val callbacks = RecordingCallbacks().apply {
                setCertificates(issued.certificateChain)
            }

            val response = harness.verify(issued.proof, callbacks).get(10, TimeUnit.SECONDS)

            response.shouldBeInstanceOf<AttestationResponse.Success>()
                .certificateChain shouldBe issued.certificateChain
            callbacks.calls shouldBe listOf("challenge", "additional", "issuer", "success")
            callbacks.validatedChallenge shouldBe issued.challenge
            callbacks.validatedProof shouldBe issued.proof
            callbacks.additionalChallenge shouldBe issued.challenge
            callbacks.additionalProof shouldBe issued.proof
            callbacks.issuerProof shouldBe issued.proof
            callbacks.issuerVerified shouldBe callbacks.additionalVerified
            callbacks.successfulVerified shouldBe callbacks.additionalVerified
            callbacks.successfulPublicKey shouldBe issued.proof.data.tbsCsr.publicKey
            callbacks.preAttestationError shouldBe null
            callbacks.attestationError shouldBe null
        }

        test("Java additional verification can reject and skips issuer and success callbacks") { fixture ->
            val harness = fixture.javaHarness()
            val issued = fixture.issueJavaProof(harness)
            val rejection = AttestationResponse.Failure(
                AttestationResponse.Failure.Type.TRUST,
                "rejected by Java policy",
            )
            val callbacks = RecordingCallbacks().apply {
                setAdditionalFailure(rejection)
                setCertificates(issued.certificateChain)
            }

            val response = harness.verify(issued.proof, callbacks).get(10, TimeUnit.SECONDS)

            response shouldBe rejection
            callbacks.calls shouldBe listOf("challenge", "additional")
            callbacks.additionalChallenge shouldBe issued.challenge
            callbacks.additionalProof shouldBe issued.proof
            callbacks.issuerProof shouldBe null
            callbacks.successfulVerified shouldBe null
        }

        test("attestation failures reach the Java error callback with debug information") { fixture ->
            val harness = fixture.javaHarness(packageName = "com.example.not-the-attested-app")
            val issued = fixture.issueJavaProof(harness)
            val callbacks = RecordingCallbacks().apply {
                setAttestationErrorExplanation("Java saw the policy failure")
            }

            val response = harness.verify(issued.proof, callbacks).get(10, TimeUnit.SECONDS)

            response.shouldBeInstanceOf<AttestationResponse.Failure>().also {
                it.kind shouldBe AttestationResponse.Failure.Type.CONTENT
                it.explanation shouldBe "Java saw the policy failure"
            }
            callbacks.calls shouldBe listOf("challenge", "attestation-error")
            callbacks.attestationError.shouldBeInstanceOf<at.asitplus.attestation.AttestationResult.Error>()
            callbacks.debugInfo.challenge?.contentEquals(issued.challenge.nonce) shouldBe true
            callbacks.preAttestationError shouldBe null
        }

        test("issuer exceptions map to an internal response and invoke the Java pre-error callback") { fixture ->
            val harness = fixture.javaHarness()
            val issued = fixture.issueJavaProof(harness)
            val callbacks = RecordingCallbacks().apply {
                setIssuerException(IllegalStateException("issuer exploded"))
                setPreErrorExplanation("Java issuer failed")
            }

            val response = harness.verify(issued.proof, callbacks).get(10, TimeUnit.SECONDS)

            response.shouldBeInstanceOf<AttestationResponse.Failure>().also {
                it.kind shouldBe AttestationResponse.Failure.Type.INTERNAL
                it.explanation shouldBe "Java issuer failed"
            }
            callbacks.calls shouldBe listOf("challenge", "additional", "issuer", "pre-error")
            callbacks.preAttestationError.shouldBeInstanceOf<PreAttestationError.OperationalError>()
            callbacks.successfulVerified shouldBe null
        }

        test("Java observation callback exceptions remain side-effect only") { fixture ->
            val harness = fixture.javaHarness()
            val issued = fixture.issueJavaProof(harness)
            val callbacks = RecordingCallbacks().apply {
                setCertificates(issued.certificateChain)
                setThrowOnChallengeValidated(true)
                setThrowOnAttestationSuccess(true)
            }

            harness.verify(issued.proof, callbacks).get(10, TimeUnit.SECONDS)
                .shouldBeInstanceOf<AttestationResponse.Success>()
            callbacks.calls shouldBe listOf("challenge", "additional", "issuer", "success")
        }

        test("concurrent Java challenge futures complete with distinct nonces") { fixture ->
            val harness = fixture.javaHarness()
            val futures = List(32) { harness.issueChallenge("$attestationEndpoint/$it") }

            CompletableFuture.allOf(*futures.toTypedArray()).get(10, TimeUnit.SECONDS)
            val challenges = futures.map { it.join() }

            challenges shouldHaveSize 32
            challenges.map { it.attestationEndpoint }.toSet() shouldHaveSize 32
            challenges.map { Base64.getEncoder().encodeToString(it.nonce) }.toSet() shouldHaveSize 32
        }
    }
}
