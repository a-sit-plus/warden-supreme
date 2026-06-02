@file:OptIn(kotlin.time.ExperimentalTime::class)

package at.asitplus.attestation.supreme

import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withData
import at.asitplus.testballoon.withFixtureGenerator
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import java.security.MessageDigest
import java.util.Date
import kotlin.random.Random
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequest

val AttestationVerifierFakeAndroidTest by testSuite(
    testConfig = TestConfig.invocation(TestConfig.Invocation.Sequential)
) {
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

        test("additional verifications run after attestation and before certificate issuer") { fixture ->
            val verifier = fixture.verifier(fixture.trustedConfig())
            val csr = fixture.issueCsr(verifier)
            val calls = mutableListOf<String>()

            val response = verifier.verifyAttestation(
                csr,
                additionalVerifications = { receivedCsr, _ ->
                    calls += "additional"
                    receivedCsr shouldBe csr
                    nonce.contentEquals(fixture.nonce) shouldBe true
                    null
                },
                certificateIssuer = {
                    calls += "issuer"
                    emptyList()
                }
            )

            response.shouldBeInstanceOf<AttestationResponse.Success>()
            calls shouldBe listOf("additional", "issuer")
        }

        test("additional verification failure returns custom failure and skips certificate issuer") { fixture ->
            val verifier = fixture.verifier(fixture.trustedConfig())
            val csr = fixture.issueCsr(verifier)
            val calls = mutableListOf<String>()
            val customFailure = AttestationResponse.Failure(
                AttestationResponse.Failure.Type.CONTENT,
                "tenant policy rejected"
            )

            val response = verifier.verifyAttestation(
                csr,
                additionalVerifications = { _, _ ->
                    calls += "additional"
                    customFailure
                },
                certificateIssuer = {
                    calls += "issuer"
                    emptyList()
                }
            )

            response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
                failure.kind shouldBe customFailure.kind
                failure.explanation shouldBe customFailure.explanation
            }
            calls.shouldHaveSize(1)
            calls.single() shouldBe "additional"
        }

        test("additional verification exception maps to internal failure and skips certificate issuer") { fixture ->
            val verifier = fixture.verifier(fixture.trustedConfig())
            val csr = fixture.issueCsr(verifier)
            val calls = mutableListOf<String>()

            val response = verifier.verifyAttestation(
                csr,
                additionalVerifications = { _, _ ->
                    calls += "additional"
                    error("custom policy exploded")
                },
                certificateIssuer = {
                    calls += "issuer"
                    emptyList()
                }
            )

            response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
                failure.kind shouldBe AttestationResponse.Failure.Type.INTERNAL
                failure.explanation shouldBe "Custom checks failed"
            }
            calls.shouldHaveSize(1)
            calls.single() shouldBe "additional"
        }

        test("custom check failure consumes challenge so csr cannot be replayed") { fixture ->
            val verifier = fixture.verifier(fixture.trustedConfig())
            val csr = fixture.issueCsr(verifier)

            val policyFailure = verifier.verifyAttestation(
                csr,
                additionalVerifications = { _, _ ->
                    AttestationResponse.Failure(
                        AttestationResponse.Failure.Type.CONTENT,
                        "tenant policy rejected"
                    )
                },
                certificateIssuer = { emptyList() }
            )

            policyFailure.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
                failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
                failure.explanation shouldBe "tenant policy rejected"
            }

            val replay = verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
            replay.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
                failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
            }
        }

        test("additional verifications do not run when generic attestation fails") { fixture ->
            val verifier = fixture.verifier(fixture.trustedConfig(packageName = "com.example.other"))
            val csr = fixture.issueCsr(verifier)
            val calls = mutableListOf<String>()

            val response = verifier.verifyAttestation(
                csr,
                additionalVerifications = { _, _ ->
                    calls += "additional"
                    null
                },
                certificateIssuer = {
                    calls += "issuer"
                    emptyList()
                }
            )

            response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
                failure.kind shouldBe AttestationResponse.Failure.Type.CONTENT
            }
            calls.shouldHaveSize(0)
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
