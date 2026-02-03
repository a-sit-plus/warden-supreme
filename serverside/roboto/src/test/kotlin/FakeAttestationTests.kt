package at.asitplus.attestation.android

import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.attestation.android.exceptions.CertificateInvalidException
import at.asitplus.attestation.data.AttestationCreator
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
        withData(nameFn = { "Experimental Parser = $it" }, false, true) - { experimental ->

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
                    experimentalParser = experimental
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
                        experimentalParser = experimental
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
                            experimentalParser = experimental
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
                            experimentalParser = experimental
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
                                experimentalParser = experimental
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
                            experimentalParser = experimental
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
                            experimentalParser = experimental
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
                        experimentalParser = experimental
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
                            experimentalParser = experimental
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
                            experimentalParser = experimental
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
                        experimentalParser = experimental
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
