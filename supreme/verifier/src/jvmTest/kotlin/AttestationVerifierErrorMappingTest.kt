@file:OptIn(kotlin.time.ExperimentalTime::class)

package at.asitplus.attestation.supreme

import at.asitplus.attestation.Makoto
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.AndroidRevocationList
import at.asitplus.attestation.android.TrustedRoot
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import java.security.MessageDigest
import java.util.Date
import java.util.Locale
import kotlin.random.Random
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

val AttestationVerifierErrorMappingTest by testSuite {
    data class MappingCase(
        val name: String,
        val expected: AttestationResponse.Failure.Type,
        val run: suspend () -> AttestationResponse,
    )

    suspend fun withFixture(block: suspend (AndroidFixture) -> AttestationResponse): AttestationResponse =
        block(generateAndroidFixture())

    withData(
        nameFn = { it.name },
        MappingCase(
            name = "maps missing nonce to CONTENT (challenge extraction)",
            expected = AttestationResponse.Failure.Type.CONTENT,
            run = {
                withFixture { fixture ->
                    val verifier = fixture.verifier(fixture.trustedConfig())
                    verifier.issueChallenge(attestationEndpoint)
                    val csr = createCsrWithoutNonce(fixture.fake.leafKeyPair, fixture.fake.attestationJson())
                    verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
                }
            },
        ),
        MappingCase(
            name = "maps unknown nonce to CONTENT (challenge validation)",
            expected = AttestationResponse.Failure.Type.CONTENT,
            run = {
                withFixture { fixture ->
                    val wrongNonce = Random(102).nextBytes(16)
                    val fake = createFakeAndroidAttestation(
                        challenge = wrongNonce,
                        packageName = fakeAndroidPackage,
                        signatureDigest = fakeAndroidSignerDigest,
                    )
                    val verifier = fixture.verifier(fixture.trustedConfig())
                    val issued = verifier.issueChallenge(attestationEndpoint)
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
                    verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
                }
            },
        ),
        MappingCase(
            name = "maps missing attestation proof to CONTENT (attestation statement extraction)",
            expected = AttestationResponse.Failure.Type.CONTENT,
            run = {
                withFixture { fixture ->
                    val verifier = fixture.verifier(fixture.trustedConfig())
                    val csr = fixture.issueCsrWithoutAttestationProof(verifier)
                    verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
                }
            },
        ),
        MappingCase(
            name = "maps untrusted root to TRUST",
            expected = AttestationResponse.Failure.Type.TRUST,
            run = {
                withFixture { fixture ->
                    val config = androidConfigForFake(
                        packageName = fakeAndroidPackage,
                        signatureDigest = fakeAndroidSignerDigest,
                    )
                    val verifier = fixture.verifier(config)
                    val csr = fixture.issueCsr(verifier)
                    verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
                }
            },
        ),
        MappingCase(
            name = "maps revocation list hits to TRUST",
            expected = AttestationResponse.Failure.Type.TRUST,
            run = {
                withFixture { fixture ->
                    val revokedSerial = fixture.fake.intermediateCertificate.serialNumber
                        .toString(16)
                        .lowercase(Locale.getDefault())
                    val revocationList = AndroidRevocationList(
                        entries = mapOf(
                            revokedSerial to AndroidRevocationList.Entry(
                                status = AndroidRevocationList.RevocationStatus.REVOKED
                            )
                        ),
                        expires = fixedClock.now() + 1.hours,
                    )
                    val appData = AndroidAttestationConfiguration.AppData.Builder(
                        fakeAndroidPackage,
                        fakeAndroidSignerDigest,
                    ).build()
                    val config = AndroidAttestationConfiguration.Builder(appData)
                        .hardwareTrustedRoots(setOf(TrustedRoot.Certificate(fixture.fake.rootCertificate)))
                        .attestationStatementValiditySeconds(300)
                        .revocation(listOf(AndroidRevocationList.InMemoryLoader.Configuration(revocationList)))
                        .build()
                    val verifier = fixture.verifier(config)
                    val csr = fixture.issueCsr(verifier)
                    verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
                }
            },
        ),
        MappingCase(
            name = "maps certificate time errors to TIME",
            expected = AttestationResponse.Failure.Type.TIME,
            run = {
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
                val verifier = verifierForNonce(fixedMakoto(config), nonce)
                val csr = createCsr(verifier.issueChallenge(attestationEndpoint), fake.attestationJson(), fake.leafKeyPair)
                verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
            },
        ),
        MappingCase(
            name = "maps statement time errors to TIME",
            expected = AttestationResponse.Failure.Type.TIME,
            run = {
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
                val verifier = verifierForNonce(fixedMakoto(config), nonce)
                val csr = createCsr(verifier.issueChallenge(attestationEndpoint), fake.attestationJson(), fake.leafKeyPair)
                verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
            },
        ),
        MappingCase(
            name = "maps package mismatch to CONTENT",
            expected = AttestationResponse.Failure.Type.CONTENT,
            run = {
                withFixture { fixture ->
                    val verifier = fixture.verifier(fixture.trustedConfig(packageName = "com.example.other"))
                    val csr = fixture.issueCsr(verifier)
                    verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
                }
            },
        ),
        MappingCase(
            name = "maps signer mismatch to CONTENT",
            expected = AttestationResponse.Failure.Type.CONTENT,
            run = {
                withFixture { fixture ->
                    val wrongSigner = MessageDigest.getInstance("SHA-256")
                        .digest("wrong-signer".encodeToByteArray())
                    val verifier = fixture.verifier(fixture.trustedConfig(signatureDigest = wrongSigner))
                    val csr = fixture.issueCsr(verifier)
                    verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
                }
            },
        ),
        MappingCase(
            name = "maps verified boot state violations to CONTENT",
            expected = AttestationResponse.Failure.Type.CONTENT,
            run = {
                withFixture { fixture ->
                    val fake = createFakeAndroidAttestationWithRoots(
                        challenge = fixture.nonce,
                        packageName = fakeAndroidPackage,
                        signatureDigest = fakeAndroidSignerDigest,
                        creationTime = Date(fixedClock.now().toEpochMilliseconds()),
                        deviceLocked = true,
                        verifiedBootState = BootState.UNVERIFIED,
                        rootKeyPair = fixture.fake.rootKeyPair,
                        rootCertificate = fixture.fake.rootCertificate,
                        intermediateKeyPair = fixture.fake.intermediateKeyPair,
                        intermediateCertificate = fixture.fake.intermediateCertificate,
                    )
                    val verifier = fixture.verifier(fixture.trustedConfig())
                    val csr = fixture.issueCsr(verifier, fake.attestationJson(), fake.leafKeyPair)
                    verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
                }
            },
        ),
        MappingCase(
            name = "maps attestation challenge mismatch to CONTENT",
            expected = AttestationResponse.Failure.Type.CONTENT,
            run = {
                withFixture { fixture ->
                    val otherNonce = Random(111).nextBytes(16)
                    val fake = createFakeAndroidAttestationWithRoots(
                        challenge = otherNonce,
                        packageName = fakeAndroidPackage,
                        signatureDigest = fakeAndroidSignerDigest,
                        creationTime = Date(fixedClock.now().toEpochMilliseconds()),
                        deviceLocked = true,
                        verifiedBootState = BootState.VERIFIED,
                        rootKeyPair = fixture.fake.rootKeyPair,
                        rootCertificate = fixture.fake.rootCertificate,
                        intermediateKeyPair = fixture.fake.intermediateKeyPair,
                        intermediateCertificate = fixture.fake.intermediateCertificate,
                    )
                    val verifier = fixture.verifier(fixture.trustedConfig())
                    val csr = fixture.issueCsr(verifier, fake.attestationJson(), fake.leafKeyPair)
                    verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
                }
            },
        ),
        MappingCase(
            name = "maps unsupported platform to CONTENT",
            expected = AttestationResponse.Failure.Type.CONTENT,
            run = {
                withFixture { fixture ->
                    val verifier = verifierForNonce(Makoto(iosConfig, clock = fixedClock, verificationTimeOffset = 0.seconds), fixture.nonce)
                    val csr = fixture.issueCsr(verifier)
                    verifier.verifyAttestation(csr, certificateIssuer = { emptyList() })
                }
            },
        ),
        MappingCase(
            name = "maps operational errors to INTERNAL",
            expected = AttestationResponse.Failure.Type.INTERNAL,
            run = {
                withFixture { fixture ->
                    val verifier = fixture.verifier(fixture.trustedConfig())
                    val csr = fixture.issueCsr(verifier)
                    verifier.verifyAttestation(csr, certificateIssuer = { error("boom") })
                }
            },
        ),
    ) { case ->
        val response = case.run()
        response.shouldBeInstanceOf<AttestationResponse.Failure>().also { failure ->
            failure.kind shouldBe case.expected
        }
    }
}
