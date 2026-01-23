@file:OptIn(kotlin.time.ExperimentalTime::class)

package at.asitplus.attestation.supreme

import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withData
import at.asitplus.testballoon.withFixtureGenerator
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import java.security.MessageDigest
import java.util.Date
import kotlin.random.Random
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequest

val AttestationVerifierFakeAndroidTest by testSuite {
    data class FailureCase(
        val name: String,
        val config: AndroidFixture.() -> AndroidAttestationConfiguration,
        val csr: suspend AndroidFixture.(AttestationVerifier) -> Pkcs10CertificationRequest = { verifier ->
            issueCsr(verifier)
        },
        val expected: AttestationResponse.Failure.Type,
    )

    withFixtureGenerator(::generateAndroidFixture) - {
        test("android fake attestation verifies with custom trusted root") { fixture ->
            val verifier = fixture.verifier(fixture.trustedConfig())
            val csr = fixture.issueCsr(verifier)

            val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
            response.shouldBeInstanceOf<AttestationResponse.Success>()
        }
    }

    withData(
        nameFn = { it.name },
        FailureCase(
            name = "android fake attestation fails without trusted root",
            config = {
                androidConfigForFake(
                    packageName = fakeAndroidPackage,
                    signatureDigest = fakeAndroidSignerDigest,
                )
            },
            expected = AttestationResponse.Failure.Type.TRUST,
        ),
        FailureCase(
            name = "android fake attestation fails on package mismatch",
            config = { trustedConfig(packageName = "com.example.other") },
            expected = AttestationResponse.Failure.Type.CONTENT,
        ),
        FailureCase(
            name = "android fake attestation fails on signer mismatch",
            config = {
                val wrongSigner = MessageDigest.getInstance("SHA-256")
                    .digest("wrong-signer".encodeToByteArray())
                trustedConfig(signatureDigest = wrongSigner)
            },
            expected = AttestationResponse.Failure.Type.CONTENT,
        ),
        FailureCase(
            name = "android fake attestation fails on challenge mismatch",
            config = { trustedConfig() },
            csr = { verifier ->
                val otherNonce = Random(6).nextBytes(16)
                val otherFake = createFakeAndroidAttestationWithRoots(
                    challenge = otherNonce,
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
                issueCsr(verifier, otherFake.attestationJson(), otherFake.leafKeyPair)
            },
            expected = AttestationResponse.Failure.Type.CONTENT,
        ),
        FailureCase(
            name = "csr missing attestation proof fails",
            config = { trustedConfig() },
            csr = { verifier -> issueCsrWithoutAttestationProof(verifier) },
            expected = AttestationResponse.Failure.Type.CONTENT,
        ),
        FailureCase(
            name = "csr with invalid attestation json fails",
            config = { trustedConfig() },
            csr = { verifier -> issueCsr(verifier, "{not-json") },
            expected = AttestationResponse.Failure.Type.CONTENT,
        ),
    ) { case ->
        val fixture = generateAndroidFixture()
        val verifier = fixture.verifier(case.config(fixture))
        val csr = case.csr(fixture, verifier)

        val response = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe case.expected
        }
    }
}
