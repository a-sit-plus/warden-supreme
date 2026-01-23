@file:OptIn(kotlin.time.ExperimentalTime::class)

package at.asitplus.attestation.supreme

import at.asitplus.attestation.AttestationResult
import at.asitplus.attestation.Makoto
import at.asitplus.attestation.WardenDebugAttestationStatement
import at.asitplus.attestation.android.TrustedRoot
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.withClue
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.random.Random
import kotlin.text.HexFormat
import kotlin.time.Duration.Companion.seconds

val AttestationVerifierCallbackTest by testSuite {
    "reports challenge extraction failures via onPreAttestationError" {
        val nonce = Random(200).nextBytes(16)
        val fake = createFakeAndroidAttestation(
            challenge = nonce,
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
        )
        val config = androidConfigForFake(
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
            trustedRoots = setOf(TrustedRoot.Certificate(fake.rootCertificate)),
        )
        val verifier = verifierForNonce(
            Makoto(config, clock = fixedClock, verificationTimeOffset = 0.seconds),
            nonce
        )
        verifier.issueChallenge("https://example.invalid/attest")
        val csr = createCsrWithoutNonce(fake.leafKeyPair, fake.attestationJson())

        val preErrors = mutableListOf<PreAttestationError>()
        val attErrors = mutableListOf<AttestationResult.Error>()
        val response = verifier.verifyAttestation(
            csr,
            onPreAttestationError = {
                preErrors += this
                "pre"
            },
            onAttestationError = {
                attErrors += this
                "att"
            },
            certificateIssuer = { emptyList() }
        )

        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
            failure.explanation shouldBe "pre"
        }
        preErrors shouldHaveSize 1
        preErrors.single().shouldBeInstanceOf<PreAttestationError.ChallengeExtraction>()
        attErrors shouldHaveSize 0
    }

    "reports challenge verification failures via onPreAttestationError" {
        val nonce = Random(201).nextBytes(16)
        val wrongNonce = Random(202).nextBytes(16)
        val fake = createFakeAndroidAttestation(
            challenge = wrongNonce,
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
        )
        val config = androidConfigForFake(
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
            trustedRoots = setOf(TrustedRoot.Certificate(fake.rootCertificate)),
        )
        val verifier = verifierForNonce(
            Makoto(config, clock = fixedClock, verificationTimeOffset = 0.seconds),
            nonce
        )
        val issued = verifier.issueChallenge("https://example.invalid/attest")
        val csrChallenge = AttestationChallenge(
            issuedAt = issued.issuedAt,
            validity = issued.validity,
            timeZone = issued.timeZone,
            nonce = wrongNonce,
            attestationEndpoint = issued.attestationEndpoint,
            proofOID = issued.proofOID,
            genericDeviceNameOID = issued.genericDeviceNameOID,
            keyConstraints = issued.keyConstraints,
        )
        val csr = createCsr(csrChallenge, fake.attestationJson(), fake.leafKeyPair)

        val preErrors = mutableListOf<PreAttestationError>()
        val response = verifier.verifyAttestation(
            csr,
            onPreAttestationError = {
                preErrors += this
                "pre"
            },
            certificateIssuer = { emptyList() }
        )

        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
            failure.explanation shouldBe "pre"
        }
        preErrors shouldHaveSize 1
        val error = preErrors.single().shouldBeInstanceOf<PreAttestationError.ChallengeVerification>()
        error.receivedChallenge.contentEquals(wrongNonce) shouldBe true
    }

    "reports attestation statement extraction failures via onPreAttestationError" {
        val nonce = Random(203).nextBytes(16)
        val fake = createFakeAndroidAttestation(
            challenge = nonce,
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
        )
        val config = androidConfigForFake(
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
            trustedRoots = setOf(TrustedRoot.Certificate(fake.rootCertificate)),
        )
        val verifier = verifierForNonce(
            Makoto(config, clock = fixedClock, verificationTimeOffset = 0.seconds),
            nonce
        )
        val challenge = verifier.issueChallenge("https://example.invalid/attest")
        val csr = createCsrWithAttributes(challenge, fake.leafKeyPair, attributes = emptyList())

        val preErrors = mutableListOf<PreAttestationError>()
        val response = verifier.verifyAttestation(
            csr,
            onPreAttestationError = {
                preErrors += this
                "pre"
            },
            certificateIssuer = { emptyList() }
        )

        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
            failure.explanation shouldBe "pre"
        }
        preErrors shouldHaveSize 1
        preErrors.single().shouldBeInstanceOf<PreAttestationError.AttestationStatementExtraction>()
    }

    "reports operational errors via onPreAttestationError" {
        val nonce = Random(204).nextBytes(16)
        val fake = createFakeAndroidAttestation(
            challenge = nonce,
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
        )
        val config = androidConfigForFake(
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
            trustedRoots = setOf(TrustedRoot.Certificate(fake.rootCertificate)),
        )
        val verifier = verifierForNonce(
            Makoto(config, clock = fixedClock, verificationTimeOffset = 0.seconds),
            nonce
        )
        val challenge = verifier.issueChallenge("https://example.invalid/attest")
        val csr = createCsr(challenge, fake.attestationJson(), fake.leafKeyPair)

        val preErrors = mutableListOf<PreAttestationError>()
        val response = verifier.verifyAttestation(
            csr,
            onPreAttestationError = {
                preErrors += this
                "pre"
            },
            certificateIssuer = { error("boom") }
        )

        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.INTERNAL
            failure.explanation shouldBe "pre"
        }
        preErrors shouldHaveSize 1
        preErrors.single().shouldBeInstanceOf<PreAttestationError.OperationalError>()
    }

    "reports attestation failures via onAttestationError" {
        val nonce = Random(205).nextBytes(16)
        val fake = createFakeAndroidAttestation(
            challenge = nonce,
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
        )
        val config = androidConfigForFake(
            packageName = "com.example.other",
            signatureDigest = fakeAndroidSignerDigest,
            trustedRoots = setOf(TrustedRoot.Certificate(fake.rootCertificate)),
        )
        val verifier = verifierForNonce(
            Makoto(config, clock = fixedClock, verificationTimeOffset = 0.seconds),
            nonce
        )
        val challenge = verifier.issueChallenge("https://example.invalid/attest")
        val csr = createCsr(challenge, fake.attestationJson(), fake.leafKeyPair)

        val preErrors = mutableListOf<PreAttestationError>()
        val attErrors = mutableListOf<AttestationResult.Error>()
        val debugInfos = mutableListOf<WardenDebugAttestationStatement>()
        val response = verifier.verifyAttestation(
            csr,
            onPreAttestationError = {
                preErrors += this
                "pre"
            },
            onAttestationError = { debugInfo ->
                attErrors += this
                debugInfos += debugInfo
                "att"
            },
            certificateIssuer = { emptyList() }
        )

        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
            failure.explanation shouldBe "att"
        }
        preErrors shouldHaveSize 0
        attErrors shouldHaveSize 1
        debugInfos shouldHaveSize 1
        withClue("expected debug info to carry the issued nonce") {
            debugInfos.single().challenge?.contentEquals(nonce) shouldBe true
        }
    }

    "reports CSR signature failures via onAttestationError" {
        val case = e2eCases.first()
        val nonce = case.nonceHex.hexToByteArray(HexFormat.UpperCase)
        val verifier = verifierForNonce(nonce)
        val challenge = verifier.issueChallenge("https://example.invalid/attest")
        val attestationJson = loadResourceText(case.attestationResource)
        val csr = createCsr(challenge, attestationJson, keyPairForAttestation(attestationJson))

        val attErrors = mutableListOf<AttestationResult.Error>()
        val debugInfos = mutableListOf<WardenDebugAttestationStatement>()
        val response = verifier.verifyAttestation(
            csr,
            onAttestationError = { debugInfo ->
                attErrors += this
                debugInfos += debugInfo
                "att"
            },
            certificateIssuer = { emptyList() }
        )

        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.TRUST
            failure.explanation shouldBe "att"
        }
        attErrors shouldHaveSize 1
        debugInfos shouldHaveSize 1
    }
}
