@file:OptIn(kotlin.time.ExperimentalTime::class)

package at.asitplus.attestation.supreme

import at.asitplus.attestation.Makoto
import at.asitplus.attestation.android.TrustedRoot
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import java.security.MessageDigest
import kotlin.random.Random
import kotlin.time.Duration.Companion.seconds

val AttestationVerifierFakeAndroidTest by testSuite {
    "android fake attestation verifies with custom trusted root" {
        val nonce = Random(1).nextBytes(16)
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

        val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
        response.shouldBeInstanceOf<AttestationResponse.Success>()
    }

    "android fake attestation fails without trusted root" {
        val nonce = Random(2).nextBytes(16)
        val fake = createFakeAndroidAttestation(
            challenge = nonce,
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
        )
        val config = androidConfigForFake(
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
        )
        val verifier = verifierForNonce(
            Makoto(config, clock = fixedClock, verificationTimeOffset = 0.seconds),
            nonce
        )
        val challenge = verifier.issueChallenge("https://example.invalid/attest")
        val csr = createCsr(challenge, fake.attestationJson(), fake.leafKeyPair)

        val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.TRUST
        }
    }

    "android fake attestation fails on package mismatch" {
        val nonce = Random(3).nextBytes(16)
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

        val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
        }
    }

    "android fake attestation fails on signer mismatch" {
        val nonce = Random(4).nextBytes(16)
        val fake = createFakeAndroidAttestation(
            challenge = nonce,
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
        )
        val wrongSigner = MessageDigest.getInstance("SHA-256").digest("wrong-signer".encodeToByteArray())
        val config = androidConfigForFake(
            packageName = fakeAndroidPackage,
            signatureDigest = wrongSigner,
            trustedRoots = setOf(TrustedRoot.Certificate(fake.rootCertificate)),
        )
        val verifier = verifierForNonce(
            Makoto(config, clock = fixedClock, verificationTimeOffset = 0.seconds),
            nonce
        )
        val challenge = verifier.issueChallenge("https://example.invalid/attest")
        val csr = createCsr(challenge, fake.attestationJson(), fake.leafKeyPair)

        val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
        }
    }

    "android fake attestation fails on challenge mismatch" {
        val nonce = Random(5).nextBytes(16)
        val otherNonce = Random(6).nextBytes(16)
        val fake = createFakeAndroidAttestation(
            challenge = otherNonce,
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

        val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
        }
    }

    "csr missing attestation proof fails" {
        val nonce = Random(7).nextBytes(16)
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

        val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
        }
    }

    "csr with invalid attestation json fails" {
        val nonce = Random(8).nextBytes(16)
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
        val csr = createCsr(challenge, "{not-json", fake.leafKeyPair)

        val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
        }
    }
}
