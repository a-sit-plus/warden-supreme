package at.asitplus.attestation.android

import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.attestation.android.exceptions.CertificateInvalidException
import at.asitplus.attestation.data.AttestationCreator
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import java.time.YearMonth
import java.time.ZoneOffset
import java.util.*
import kotlin.random.Random

class FakeAttestationTests : FreeSpec({

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

        val checker = HardwareAttestationChecker(
            AndroidAttestationConfiguration(
                AndroidAttestationConfiguration.AppData(
                    packageName = packageName,
                    signatureDigests = listOf(signatureDigest),
                    appVersion = appVersion
                ),
                androidVersion = androidVersion,
                patchLevel = patchLevel,
                requireStrongBox = false,
                allowBootloaderUnlock = false,
                ignoreLeafValidity = false,
                hardwareAttestationTrustAnchors = setOf(attestationProof.last().publicKey)
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

            HardwareAttestationChecker(
                AndroidAttestationConfiguration(
                    AndroidAttestationConfiguration.AppData(
                        packageName = packageName,
                        signatureDigests = listOf(signatureDigest),
                        appVersion = appVersion
                    ),
                    androidVersion = androidVersion,
                    patchLevel = patchLevel,
                    requireStrongBox = false,
                    allowBootloaderUnlock = false,
                    ignoreLeafValidity = false,
                    hardwareAttestationTrustAnchors = setOf(borkedAttestation.last().publicKey)
                )
            ).verifyAttestation(
                certificates = borkedAttestation,
                expectedChallenge = challenge
            )
        }


        "should work when the fake cert is configured as trust anchor" {
            checker.verifyAttestation(
                certificates = attestationProof,
                expectedChallenge = challenge
            )
        }

        "patch levels from the future" - {

            val yearMonth = YearMonth.of(patchLevel.year, patchLevel.month)
            val verificationDate = Date(
                yearMonth
                    .atDay(1)
                    .atStartOfDay(ZoneOffset.UTC)
                    .toInstant().toEpochMilli()
            )

            "within default tolerance" {

                val attestationProof = AttestationCreator.createAttestation(
                    challenge = challenge,
                    packageName = packageName,
                    signatureDigest = signatureDigest,
                    appVersion = appVersion,
                    androidVersion = androidVersion,
                    androidPatchLevel = patchLevel.asSingleInt,
                    creationTime = verificationDate,
                )

                HardwareAttestationChecker(
                    AndroidAttestationConfiguration(
                        AndroidAttestationConfiguration.AppData(
                            packageName = packageName,
                            signatureDigests = listOf(signatureDigest),
                            appVersion = appVersion
                        ),
                        androidVersion = androidVersion,
                        patchLevel = patchLevel,
                        requireStrongBox = false,
                        allowBootloaderUnlock = false,
                        ignoreLeafValidity = false,
                        hardwareAttestationTrustAnchors = setOf(attestationProof.last().publicKey)
                    )
                ).verifyAttestation(
                    certificates = attestationProof,
                    expectedChallenge = challenge,
                    verificationDate = verificationDate
                )
            }

            "intolerant towards the future" {

                val attestationProof = AttestationCreator.createAttestation(
                    challenge = challenge,
                    packageName = packageName,
                    signatureDigest = signatureDigest,
                    appVersion = appVersion,
                    androidVersion = androidVersion,
                    androidPatchLevel = patchLevel.asSingleInt + 1, // advance one month
                    creationTime = verificationDate,
                )

                HardwareAttestationChecker(
                    AndroidAttestationConfiguration(
                        AndroidAttestationConfiguration.AppData(
                            packageName = packageName,
                            signatureDigests = listOf(signatureDigest),
                            appVersion = appVersion
                        ),
                        androidVersion = androidVersion,
                        patchLevel = patchLevel, // HERE we use the default patch level that allows 1 month into the future
                        requireStrongBox = false,
                        allowBootloaderUnlock = false,
                        ignoreLeafValidity = false,
                        hardwareAttestationTrustAnchors = setOf(attestationProof.last().publicKey)
                    )
                ).verifyAttestation(
                    certificates = attestationProof,
                    expectedChallenge = challenge,
                    verificationDate = verificationDate
                )

                shouldThrow<AttestationValueException> {
                    HardwareAttestationChecker(
                        AndroidAttestationConfiguration(
                            AndroidAttestationConfiguration.AppData(
                                packageName = packageName,
                                signatureDigests = listOf(signatureDigest),
                                appVersion = appVersion
                            ),
                            androidVersion = androidVersion,
                            //here we don't allow patch levels from the future
                            patchLevel = PatchLevel(patchLevel.year, patchLevel.month, maxFuturePatchLevelMonths = 0),
                            requireStrongBox = false,
                            allowBootloaderUnlock = false,
                            ignoreLeafValidity = false,
                            hardwareAttestationTrustAnchors = setOf(attestationProof.last().publicKey)
                        )
                    ).verifyAttestation(
                        certificates = attestationProof,
                        expectedChallenge = challenge,

                        verificationDate = verificationDate
                    )
                }



                //now we verify for the same month without tolerance. this should work
                val attestationProofSameMonth = AttestationCreator.createAttestation(
                    challenge = challenge,
                    packageName = packageName,
                    signatureDigest = signatureDigest,
                    appVersion = appVersion,
                    androidVersion = androidVersion,
                    androidPatchLevel = patchLevel.asSingleInt,
                    creationTime = verificationDate,
                )

                HardwareAttestationChecker(
                    AndroidAttestationConfiguration(
                        AndroidAttestationConfiguration.AppData(
                            packageName = packageName,
                            signatureDigests = listOf(signatureDigest),
                            appVersion = appVersion
                        ),
                        androidVersion = androidVersion,
                        //here we don't allow patch levels from the future
                        patchLevel = PatchLevel(patchLevel.year, patchLevel.month, maxFuturePatchLevelMonths = 0),
                        requireStrongBox = false,
                        allowBootloaderUnlock = false,
                        ignoreLeafValidity = false,
                        hardwareAttestationTrustAnchors = setOf(attestationProofSameMonth.last().publicKey)
                    )
                ).verifyAttestation(
                    certificates = attestationProofSameMonth,
                    expectedChallenge = challenge,

                    verificationDate = verificationDate
                )
            }

            "ignore future patch levels" {
                val attestationProof = AttestationCreator.createAttestation(
                    challenge = challenge,
                    packageName = packageName,
                    signatureDigest = signatureDigest,
                    appVersion = appVersion,
                    androidVersion = androidVersion,
                    androidPatchLevel = patchLevel.asSingleInt + 300,
                    creationTime = verificationDate,
                )

                HardwareAttestationChecker(
                    AndroidAttestationConfiguration(
                        AndroidAttestationConfiguration.AppData(
                            packageName = packageName,
                            signatureDigests = listOf(signatureDigest),
                            appVersion = appVersion
                        ),
                        androidVersion = androidVersion,
                        patchLevel = PatchLevel(patchLevel.year, patchLevel.month, maxFuturePatchLevelMonths = null),
                        requireStrongBox = false,
                        allowBootloaderUnlock = false,
                        ignoreLeafValidity = false,
                        hardwareAttestationTrustAnchors = setOf(attestationProof.last().publicKey)
                    )
                ).verifyAttestation(
                    certificates = attestationProof,
                    expectedChallenge = challenge,

                    verificationDate = verificationDate
                )
            }

        }

        "but not with a real cert from a real device" - {

            val checker = HardwareAttestationChecker(
                AndroidAttestationConfiguration(
                    AndroidAttestationConfiguration.AppData(
                        packageName = packageName,
                        signatureDigests = listOf(signatureDigest),
                        appVersion = appVersion
                    ),
                    androidVersion = androidVersion,
                    patchLevel = patchLevel,
                    requireStrongBox = false,
                    allowBootloaderUnlock = false,
                    ignoreLeafValidity = false,
                )
            )

            shouldThrow<CertificateInvalidException> {
                checker.verifyAttestation(attestationProof, expectedChallenge = challenge)
            }.reason shouldBe CertificateInvalidException.Reason.TRUST

            "unless overridden" {
                val checker = HardwareAttestationChecker(
                    AndroidAttestationConfiguration(
                        AndroidAttestationConfiguration.AppData(
                            packageName = packageName,
                            signatureDigests = listOf(signatureDigest),
                            appVersion = appVersion,
                            trustAnchorOverrides = setOf(attestationProof.last().publicKey)
                        ),
                        androidVersion = androidVersion,
                        patchLevel = patchLevel,
                        requireStrongBox = false,
                        allowBootloaderUnlock = false,
                        ignoreLeafValidity = false,
                    )
                )
                checker.verifyAttestation(
                    certificates = attestationProof,
                    expectedChallenge = challenge
                )
            }

            shouldThrow<CertificateInvalidException> {
                checker.verifyAttestation(attestationProof, expectedChallenge = challenge)
            }.reason shouldBe CertificateInvalidException.Reason.TRUST

            "but never without trust anchors" {
                val checker = HardwareAttestationChecker(
                    AndroidAttestationConfiguration(
                        AndroidAttestationConfiguration.AppData(
                            packageName = packageName,
                            signatureDigests = listOf(signatureDigest),
                            appVersion = appVersion,
                            trustAnchorOverrides = setOf()
                        ),
                        androidVersion = androidVersion,
                        patchLevel = patchLevel,
                        requireStrongBox = false,
                        allowBootloaderUnlock = false,
                        ignoreLeafValidity = false,
                    )
                )
                shouldThrow<CertificateInvalidException> {
                    checker.verifyAttestation(attestationProof, expectedChallenge = challenge)
                }.reason shouldBe CertificateInvalidException.Reason.TRUST
            }

        }

        "and the fake attestation must not verify against the google root key" {
            val trustedChecker = HardwareAttestationChecker(
                AndroidAttestationConfiguration(
                    applications = listOf(
                        AndroidAttestationConfiguration.AppData(
                            packageName = packageName,
                            signatureDigests = listOf(signatureDigest),
                            appVersion = appVersion,
                        )
                    ),
                    androidVersion = androidVersion,
                    patchLevel = patchLevel,
                    requireStrongBox = false,
                    allowBootloaderUnlock = false,
                    ignoreLeafValidity = false
                )
            )
            shouldThrow<CertificateInvalidException> {
                trustedChecker.verifyAttestation(
                    certificates = attestationProof,
                    expectedChallenge = challenge
                )
            }.reason shouldBe CertificateInvalidException.Reason.TRUST
        }


    }

})