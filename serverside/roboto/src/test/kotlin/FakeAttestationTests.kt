package at.asitplus.attestation.android

import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.attestation.android.exceptions.CertificateInvalidException
import at.asitplus.attestation.data.AttestationCreator
import at.asitplus.attestation.data.BootState
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import java.time.YearMonth
import java.time.ZoneOffset
import java.util.*
import kotlin.random.Random
import kotlin.time.toKotlinInstant

val FakeAttestationTests by testSuite {

    "Fake Attestation Test" - {
        val challenge = "42".encodeToByteArray()
        val packageName = "fa.ke.it.till.you.make.it"
        val signatureDigest = Random.nextBytes(32)
        val appVersion = 5
        val androidVersion = 11
        val patchLevel = PatchLevel(2021, 8)

        val attestationProof = AttestationCreator.createAttestation(
            challenge = challenge,
            packageName = packageName,
            signatureDigest = signatureDigest,
            appVersion = appVersion,
            androidVersion = androidVersion,
            androidPatchLevel = patchLevel.asSingleInt,
        )
        withData(nameFn = { "supreme Parser = $it" }, false, true) - { supreme ->

            val checker = Roboto(
                AndroidAttestationConfiguration(
                    AndroidAttestationConfiguration.AppData(
                        packageName = packageName,
                        signerFingerprints = listOf(signatureDigest),
                        appVersion = appVersion
                    ),
                    androidVersion = androidVersion,
                    patchLevel = patchLevel,
                    requireStrongBox = false,
                    allowBootloaderUnlock = false,
                    ignoreLeafValidity = false,
                    hardwareTrustedRoots = setOf(TrustedRoot.PublicKey(attestationProof.last().publicKey)),
                    supremeParser = supreme
                )
            )

            "Bug 77" {
                val borkedAttestation = AttestationCreator.createAttestation(
                    challenge = challenge,
                    packageName = packageName,
                    signatureDigest = signatureDigest,
                    appVersion = appVersion,
                    androidVersion = androidVersion,
                    vendorPatchLevel = 0,
                )

                Roboto(
                    AndroidAttestationConfiguration(
                        AndroidAttestationConfiguration.AppData(
                            packageName = packageName,
                            signerFingerprints = listOf(signatureDigest),
                            appVersion = appVersion
                        ),
                        androidVersion = androidVersion,
                        patchLevel = patchLevel,
                        requireStrongBox = false,
                        allowBootloaderUnlock = false,
                        ignoreLeafValidity = false,
                        hardwareTrustedRoots = setOf(TrustedRoot.PublicKey(borkedAttestation.last().publicKey)),
                        supremeParser = supreme
                    )
                ).verify(
                    certificates = borkedAttestation,
                    expectedChallenge = challenge
                ).getOrThrow()
            }


            "should work when the fake cert is configured as trust anchor" {
                checker.verify(
                    certificates = attestationProof,
                    expectedChallenge = challenge
                ).getOrThrow()
            }

            "verified boot key policies" - {
                val oemBootKey = Random.nextBytes(32)
                val customBootKey = Random.nextBytes(32)
                val verifiedAttestation = AttestationCreator.createAttestation(
                    challenge = challenge,
                    packageName = packageName,
                    signatureDigest = signatureDigest,
                    appVersion = appVersion,
                    androidVersion = androidVersion,
                    androidPatchLevel = patchLevel.asSingleInt,
                    verifiedBootKey = oemBootKey,
                    verifiedBootState = BootState.VERIFIED,
                )
                val selfSignedAttestation = AttestationCreator.createAttestation(
                    challenge = challenge,
                    packageName = packageName,
                    signatureDigest = signatureDigest,
                    appVersion = appVersion,
                    androidVersion = androidVersion,
                    androidPatchLevel = patchLevel.asSingleInt,
                    verifiedBootKey = customBootKey,
                    verifiedBootState = BootState.SELF_SIGNED,
                )

                fun checkerFor(
                    certificates: List<java.security.cert.X509Certificate>,
                    keys: Set<VerifiedBootKey>,
                    appKeys: Set<VerifiedBootKey>? = null
                ) = Roboto(
                    AndroidAttestationConfiguration(
                        AndroidAttestationConfiguration.AppData(
                            packageName = packageName,
                            signerFingerprints = listOf(signatureDigest),
                            appVersion = appVersion,
                            verifiedBootKeys = appKeys
                        ),
                        androidVersion = androidVersion,
                        patchLevel = patchLevel,
                        allowBootloaderUnlock = false,
                        ignoreLeafValidity = false,
                        hardwareTrustedRoots = setOf(TrustedRoot.PublicKey(certificates.last().publicKey)),
                        verifiedBootKeys = keys,
                        supremeParser = supreme
                    )
                )

                "OEM-only accepts VERIFIED" {
                    checkerFor(
                        verifiedAttestation,
                        linkedSetOf(VerifiedBootKey.OEM)
                    ).verify(certificates = verifiedAttestation, expectedChallenge = challenge).getOrThrow()
                }

                "OEM-only rejects SELF_SIGNED" {
                    shouldThrow<AttestationValueException> {
                        checkerFor(
                            selfSignedAttestation,
                            linkedSetOf(VerifiedBootKey.OEM)
                        ).verify(certificates = selfSignedAttestation, expectedChallenge = challenge).getOrThrow()
                    }
                }

                "custom-only accepts matching SELF_SIGNED and rejects VERIFIED" {
                    checkerFor(
                        selfSignedAttestation,
                        linkedSetOf(VerifiedBootKey.Digest(customBootKey))
                    ).verify(certificates = selfSignedAttestation, expectedChallenge = challenge).getOrThrow()

                    shouldThrow<AttestationValueException> {
                        checkerFor(
                            verifiedAttestation,
                            linkedSetOf(VerifiedBootKey.Digest(customBootKey))
                        ).verify(certificates = verifiedAttestation, expectedChallenge = challenge).getOrThrow()
                    }
                }

                "OEM plus custom accepts both" {
                    val policy = linkedSetOf(VerifiedBootKey.OEM, VerifiedBootKey.Digest(customBootKey))
                    checkerFor(verifiedAttestation, policy).verify(certificates = verifiedAttestation, expectedChallenge = challenge).getOrThrow()
                    checkerFor(selfSignedAttestation, policy).verify(certificates = selfSignedAttestation, expectedChallenge = challenge).getOrThrow()
                }

                "app-specific verified boot keys override global policy" {
                    checkerFor(
                        selfSignedAttestation,
                        linkedSetOf(VerifiedBootKey.OEM),
                        linkedSetOf(VerifiedBootKey.Digest(customBootKey))
                    ).verify(certificates = selfSignedAttestation, expectedChallenge = challenge).getOrThrow()
                }
            }

            "patch levels from the future" - {

                val yearMonth = YearMonth.of(patchLevel.year, patchLevel.month)
                val verificationDate = yearMonth
                    .atDay(1)
                    .atStartOfDay(ZoneOffset.UTC)
                    .toInstant().toKotlinInstant()


                "within default tolerance" {

                    val attestationProof = AttestationCreator.createAttestation(
                        challenge = challenge,
                        packageName = packageName,
                        signatureDigest = signatureDigest,
                        appVersion = appVersion,
                        androidVersion = androidVersion,
                        androidPatchLevel = patchLevel.asSingleInt,
                        creationTime = Date(verificationDate.toEpochMilliseconds()),
                    )

                    Roboto(
                        AndroidAttestationConfiguration(
                            AndroidAttestationConfiguration.AppData(
                                packageName = packageName,
                                signerFingerprints = listOf(signatureDigest),
                                appVersion = appVersion
                            ),
                            androidVersion = androidVersion,
                            patchLevel = patchLevel,
                            requireStrongBox = false,
                            allowBootloaderUnlock = false,
                            ignoreLeafValidity = false,
                            hardwareTrustedRoots = setOf(TrustedRoot.PublicKey(attestationProof.last().publicKey)),
                            supremeParser = supreme
                        )
                    ).verify(
                        certificates = attestationProof,
                        expectedChallenge = challenge,
                        verificationDate = verificationDate
                    ).getOrThrow()
                }

                "intolerant towards the future" {

                    val attestationProof = AttestationCreator.createAttestation(
                        challenge = challenge,
                        packageName = packageName,
                        signatureDigest = signatureDigest,
                        appVersion = appVersion,
                        androidVersion = androidVersion,
                        androidPatchLevel = patchLevel.asSingleInt + 1, // advance one month
                        creationTime = Date(verificationDate.toEpochMilliseconds()),
                    )

                    Roboto(
                        AndroidAttestationConfiguration(
                            AndroidAttestationConfiguration.AppData(
                                packageName = packageName,
                                signerFingerprints = listOf(signatureDigest),
                                appVersion = appVersion
                            ),
                            androidVersion = androidVersion,
                            patchLevel = patchLevel, // HERE we use the default patch level that allows 1 month into the future
                            requireStrongBox = false,
                            allowBootloaderUnlock = false,
                            ignoreLeafValidity = false,
                            hardwareTrustedRoots = setOf(TrustedRoot.PublicKey(attestationProof.last().publicKey)),
                            supremeParser = supreme
                        )
                    ).verify(
                        certificates = attestationProof,
                        expectedChallenge = challenge,
                        verificationDate = verificationDate
                    ).getOrThrow()

                    shouldThrow<AttestationValueException> {
                        Roboto(
                            AndroidAttestationConfiguration(
                                AndroidAttestationConfiguration.AppData(
                                    packageName = packageName,
                                    signerFingerprints = listOf(signatureDigest),
                                    appVersion = appVersion
                                ),
                                androidVersion = androidVersion,
                                //here we don't allow patch levels from the future
                                patchLevel = PatchLevel(
                                    patchLevel.year,
                                    patchLevel.month,
                                    maxFuturePatchLevelMonths = 0
                                ),
                                requireStrongBox = false,
                                allowBootloaderUnlock = false,
                                ignoreLeafValidity = false,
                                hardwareTrustedRoots = setOf(TrustedRoot.PublicKey(attestationProof.last().publicKey)),
                                supremeParser = supreme
                            )
                        ).verify(
                            certificates = attestationProof,
                            expectedChallenge = challenge,

                            verificationDate = verificationDate
                        ).getOrThrow()
                    }


                    //now we verify for the same month without tolerance. this should work
                    val attestationProofSameMonth = AttestationCreator.createAttestation(
                        challenge = challenge,
                        packageName = packageName,
                        signatureDigest = signatureDigest,
                        appVersion = appVersion,
                        androidVersion = androidVersion,
                        androidPatchLevel = patchLevel.asSingleInt,
                        creationTime = Date(verificationDate.toEpochMilliseconds()),
                    )

                    Roboto(
                        AndroidAttestationConfiguration(
                            AndroidAttestationConfiguration.AppData(
                                packageName = packageName,
                                signerFingerprints = listOf(signatureDigest),
                                appVersion = appVersion
                            ),
                            androidVersion = androidVersion,
                            //here we don't allow patch levels from the future
                            patchLevel = PatchLevel(patchLevel.year, patchLevel.month, maxFuturePatchLevelMonths = 0),
                            requireStrongBox = false,
                            allowBootloaderUnlock = false,
                            ignoreLeafValidity = false,
                            hardwareTrustedRoots = setOf(TrustedRoot.PublicKey(attestationProofSameMonth.last().publicKey)),
                            supremeParser = supreme
                        )
                    ).verify(
                        certificates = attestationProofSameMonth,
                        expectedChallenge = challenge,

                        verificationDate = verificationDate
                    ).getOrThrow()
                }

                "ignore future patch levels" {
                    val attestationProof = AttestationCreator.createAttestation(
                        challenge = challenge,
                        packageName = packageName,
                        signatureDigest = signatureDigest,
                        appVersion = appVersion,
                        androidVersion = androidVersion,
                        androidPatchLevel = patchLevel.asSingleInt + 300,
                        creationTime = Date(verificationDate.toEpochMilliseconds()),
                    )

                    Roboto(
                        AndroidAttestationConfiguration(
                            AndroidAttestationConfiguration.AppData(
                                packageName = packageName,
                                signerFingerprints = listOf(signatureDigest),
                                appVersion = appVersion
                            ),
                            androidVersion = androidVersion,
                            patchLevel = PatchLevel(
                                patchLevel.year,
                                patchLevel.month,
                                maxFuturePatchLevelMonths = null
                            ),
                            requireStrongBox = false,
                            allowBootloaderUnlock = false,
                            ignoreLeafValidity = false,
                            hardwareTrustedRoots = setOf(TrustedRoot.PublicKey(attestationProof.last().publicKey)),
                            supremeParser = supreme
                        )
                    ).verify(
                        certificates = attestationProof,
                        expectedChallenge = challenge,

                        verificationDate = verificationDate
                    ).getOrThrow()
                }

            }

            "but not with a real cert from a real device" - {

                val checker = Roboto(
                    AndroidAttestationConfiguration(
                        AndroidAttestationConfiguration.AppData(
                            packageName = packageName,
                            signerFingerprints = listOf(signatureDigest),
                            appVersion = appVersion
                        ),
                        androidVersion = androidVersion,
                        patchLevel = patchLevel,
                        requireStrongBox = false,
                        allowBootloaderUnlock = false,
                        ignoreLeafValidity = false,
                        supremeParser = supreme
                    )
                )

                "as-is" {
                    shouldThrow<CertificateInvalidException> {
                        checker.verify(attestationProof, expectedChallenge = challenge).getOrThrow()
                    }.reason shouldBe CertificateInvalidException.Reason.TRUST
                }
                "unless overridden" {
                    val checker = Roboto(
                        AndroidAttestationConfiguration(
                            AndroidAttestationConfiguration.AppData(
                                packageName = packageName,
                                signerFingerprints = listOf(signatureDigest),
                                appVersion = appVersion,
                                trustedRootOverrides = setOf(TrustedRoot.PublicKey(attestationProof.last().publicKey))
                            ),
                            androidVersion = androidVersion,
                            patchLevel = patchLevel,
                            requireStrongBox = false,
                            allowBootloaderUnlock = false,
                            ignoreLeafValidity = false,
                            supremeParser = supreme
                        )
                    )
                    checker.verify(
                        certificates = attestationProof,
                        expectedChallenge = challenge
                    ).getOrThrow()
                }

                "as-is" {
                    shouldThrow<CertificateInvalidException> {
                        checker.verify(attestationProof, expectedChallenge = challenge).getOrThrow()
                    }.reason shouldBe CertificateInvalidException.Reason.TRUST
                }
                "but never without trust anchors" {
                    val checker = Roboto(
                        AndroidAttestationConfiguration(
                            AndroidAttestationConfiguration.AppData(
                                packageName = packageName,
                                signerFingerprints = listOf(signatureDigest),
                                appVersion = appVersion,
                                trustedRootOverrides = setOf()
                            ),
                            androidVersion = androidVersion,
                            patchLevel = patchLevel,
                            requireStrongBox = false,
                            allowBootloaderUnlock = false,
                            ignoreLeafValidity = false,
                            supremeParser = supreme
                        )
                    )
                    shouldThrow<CertificateInvalidException> {
                        checker.verify(certificates = attestationProof, expectedChallenge = challenge).getOrThrow()
                    }.reason shouldBe CertificateInvalidException.Reason.TRUST
                }

            }

            "and the fake attestation must not verify against the google root key" {
                val trustedChecker = Roboto(
                    AndroidAttestationConfiguration(
                        applications = listOf(
                            AndroidAttestationConfiguration.AppData(
                                packageName = packageName,
                                signerFingerprints = listOf(signatureDigest),
                                appVersion = appVersion,
                            )
                        ),
                        androidVersion = androidVersion,
                        patchLevel = patchLevel,
                        requireStrongBox = false,
                        allowBootloaderUnlock = false,
                        ignoreLeafValidity = false,
                        attestationStatementValiditySeconds = 300,
                        supremeParser = supreme
                    )
                )
                shouldThrow<CertificateInvalidException> {
                    trustedChecker.verify(
                        certificates = attestationProof,
                        expectedChallenge = challenge
                    ).getOrThrow()
                }.reason shouldBe CertificateInvalidException.Reason.TRUST
            }


        }
    }
}
