@file:OptIn(kotlin.time.ExperimentalTime::class)

package at.asitplus.attestation.supreme

import at.asitplus.attestation.AttestationResult
import at.asitplus.attestation.WardenDebugAttestationStatement
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withData
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequest
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.withClue
import io.kotest.engine.runBlocking
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.random.Random
import kotlin.text.HexFormat

val AttestationVerifierCallbackTest by testSuite {
    data class PreErrorCase(
        val name: String,
        val csr: suspend AndroidFixture.(AttestationVerifier) -> Pkcs10CertificationRequest,
        val expected: AttestationResponse.Failure.Type,
        val expectedClass: Class<out PreAttestationError>,
        val issuer: CertificateIssuer = { emptyList() },
        val extraAssert: (PreAttestationError) -> Unit = {},
    )

    withData(
       nameFn= { it.name },
        PreErrorCase(
            name = "reports challenge extraction failures via onPreAttestationError",
            csr = { createCsrWithoutNonce(fake.leafKeyPair, fake.attestationJson()) },
            expected = AttestationResponse.Failure.Type.CONTENT,
            expectedClass = PreAttestationError.ChallengeExtraction::class.java,
        ),
        PreErrorCase(
            name = "reports challenge verification failures via onPreAttestationError",
            csr = { verifier ->
                val wrongNonce = Random(202).nextBytes(16)
                val fake = createFakeAndroidAttestation(
                    challenge = wrongNonce,
                    packageName = fakeAndroidPackage,
                    signatureDigest = fakeAndroidSignerDigest,
                )
                val issued =   verifier.issueChallenge(attestationEndpoint)
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
                createCsr(csrChallenge, fake.attestationJson(), fake.leafKeyPair)
            },
            expected = AttestationResponse.Failure.Type.CONTENT,
            expectedClass = PreAttestationError.ChallengeVerification::class.java,
            extraAssert = { error ->
                val typed = error as PreAttestationError.ChallengeVerification
            },
        ),
        PreErrorCase(
            name = "reports attestation statement extraction failures via onPreAttestationError",
            csr = { verifier -> issueCsrWithoutAttestationProof(verifier) },
            expected = AttestationResponse.Failure.Type.CONTENT,
            expectedClass = PreAttestationError.AttestationStatementExtraction::class.java,
        ),
        PreErrorCase(
            name = "reports operational errors via onPreAttestationError",
            csr = { verifier -> issueCsr(verifier) },
            expected = AttestationResponse.Failure.Type.INTERNAL,
            expectedClass = PreAttestationError.OperationalError::class.java,
            issuer = { error("boom") },
        ),
    ) { case ->
        val fixture = generateAndroidFixture()
        val verifier = fixture.verifier(fixture.trustedConfig())
        val csr = case.csr(fixture, verifier)

        val preErrors = mutableListOf<PreAttestationError>()
        val response = verifier.verifyAttestation(
            csr,
            onPreAttestationError = {
                preErrors += this
                "pre"
            },
            certificateIssuer = case.issuer
        )

        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe case.expected
            failure.explanation shouldBe "pre"
        }
        preErrors shouldHaveSize 1
        case.expectedClass.isInstance(preErrors.single()) shouldBe true
        case.extraAssert(preErrors.single())
    }

    withFixtureGenerator(::generateAndroidFixture) - {
        test("reports attestation failures via onAttestationError") { fixture ->
            val verifier = fixture.verifier(fixture.trustedConfig(packageName = "com.example.other"))
            val csr = fixture.issueCsr(verifier)

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
                debugInfos.single().challenge?.contentEquals(fixture.nonce) shouldBe true
            }
        }
    }

    withData(nameFn = { it.name }, *e2eCases.toTypedArray()) { case ->
        val nonce = case.nonceHex.hexToByteArray(HexFormat.UpperCase)
        val verifier = verifierForNonce(nonce)
        val attestationJson = loadResourceText(case.attestationResource)
        val csr = createCsr(
            verifier.issueChallenge(attestationEndpoint),
            attestationJson,
            keyPairForAttestation(attestationJson)
        )

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
