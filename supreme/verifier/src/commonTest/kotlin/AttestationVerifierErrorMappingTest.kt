@file:OptIn(kotlin.time.ExperimentalTime::class)

package at.asitplus.attestation.supreme

import at.asitplus.attestation.Makoto
import at.asitplus.attestation.android.TrustedRoot
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import java.security.MessageDigest
import java.util.Date
import kotlin.random.Random
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

val AttestationVerifierErrorMappingTest by testSuite {
    "maps missing nonce to CONTENT (challenge extraction)" {
        val nonce = Random(100).nextBytes(16)
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

        val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
        }
    }

    "maps unknown nonce to CONTENT (challenge validation)" {
        val nonce = Random(101).nextBytes(16)
        val wrongNonce = Random(102).nextBytes(16)
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

        val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
        }
    }

    "maps missing attestation proof to CONTENT (attestation statement extraction)" {
        val nonce = Random(103).nextBytes(16)
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

    "maps untrusted root to TRUST" {
        val nonce = Random(104).nextBytes(16)
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

    "maps certificate time errors to TIME" {
        val nonce = Random(105).nextBytes(16)
        val creationTime = Date(fixedClock.now().toEpochMilliseconds() - 48.hours.inWholeMilliseconds)
        val fake = createFakeAndroidAttestation(
            challenge = nonce,
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
            creationTime = creationTime,
        )
        val config = androidConfigForFake(
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
            trustedRoots = setOf(TrustedRoot.Certificate(fake.rootCertificate)),
            attestationStatementValiditySeconds = null,
            enforceLeafValidity = true,
        )
        val verifier = verifierForNonce(
            Makoto(config, clock = fixedClock, verificationTimeOffset = 0.seconds),
            nonce
        )
        val challenge = verifier.issueChallenge("https://example.invalid/attest")
        val csr = createCsr(challenge, fake.attestationJson(), fake.leafKeyPair)

        val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.TIME
        }
    }

    "maps statement time errors to TIME" {
        val nonce = Random(106).nextBytes(16)
        val creationTime = Date(fixedClock.now().toEpochMilliseconds() - 30.minutes.inWholeMilliseconds)
        val fake = createFakeAndroidAttestation(
            challenge = nonce,
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
            creationTime = creationTime,
        )
        val config = androidConfigForFake(
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
            trustedRoots = setOf(TrustedRoot.Certificate(fake.rootCertificate)),
            attestationStatementValiditySeconds = 1,
        )
        val verifier = verifierForNonce(
            Makoto(config, clock = fixedClock, verificationTimeOffset = 0.seconds),
            nonce
        )
        val challenge = verifier.issueChallenge("https://example.invalid/attest")
        val csr = createCsr(challenge, fake.attestationJson(), fake.leafKeyPair)

        val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.TIME
        }
    }

    "maps package mismatch to CONTENT" {
        val nonce = Random(107).nextBytes(16)
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

    "maps signer mismatch to CONTENT" {
        val nonce = Random(108).nextBytes(16)
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

    "maps bootloader state violations to CONTENT" {
        val nonce = Random(109).nextBytes(16)
        val fake = createFakeAndroidAttestation(
            challenge = nonce,
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
            deviceLocked = false,
            verifiedBootState = BootState.UNVERIFIED,
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

    "maps attestation challenge mismatch to CONTENT" {
        val nonce = Random(110).nextBytes(16)
        val otherNonce = Random(111).nextBytes(16)
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

    "maps unsupported platform to CONTENT" {
        val nonce = Random(112).nextBytes(16)
        val fake = createFakeAndroidAttestation(
            challenge = nonce,
            packageName = fakeAndroidPackage,
            signatureDigest = fakeAndroidSignerDigest,
        )
        val verifier = verifierForNonce(
            Makoto(iosConfig, clock = fixedClock, verificationTimeOffset = 0.seconds),
            nonce
        )
        val challenge = verifier.issueChallenge("https://example.invalid/attest")
        val csr = createCsr(challenge, fake.attestationJson(), fake.leafKeyPair)

        val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
        }
    }

    "maps operational errors to INTERNAL" {
        val nonce = Random(113).nextBytes(16)
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

        val response = verifier.verifyAttestation(
            csr,
            certificateIssuer = { error("boom") }
        )
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe AttestationResponse.Failure.Type.INTERNAL
        }
    }
}
