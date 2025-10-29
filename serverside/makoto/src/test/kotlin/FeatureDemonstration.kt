@file:OptIn(ExperimentalTime::class)

package at.asitplus.attestation

import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.PatchLevel
import at.asitplus.attestation.data.attestationCertChain
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import com.google.android.attestation.ParsedAttestationRecord
import de.infix.testBalloon.framework.testSuite
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.datetime.Instant
import java.security.interfaces.ECPublicKey
import kotlin.time.Duration
import kotlin.time.ExperimentalTime

val FeatureDemonstration by testSuite {


        val service = Warden(
            androidAttestationConfiguration = AndroidAttestationConfiguration(
                listOf(
                    AndroidAttestationConfiguration.AppData(
                        packageName = "at.asitplus.attestation_client",
                        signatureDigests = listOf("NLl2LE1skNSEMZQMV73nMUJYsmQg7+Fqx/cnTw0zCtU=".decodeBase64ToArray()),
                        appVersion = 1, //optional
                    )
                ),
                androidVersion = 10000, //optional
                patchLevel = PatchLevel(2021, 8), //optional
                requireStrongBox = false, //optional
                allowBootloaderUnlock = false, //you don't usually want to change this
                requireRollbackResistance = false, //depends on device, so leave off
                ignoreLeafValidity = false, //Hello, Samsung!
                verificationSecondsOffset = 15 * 60 - 1 * 60 * 60 + 24 * 60 * 60, //iOS and Android statements were created at different times
                attestationStatementValiditySeconds = 10*60 //But we were not that exact in the line above
            ),
            iosAttestationConfiguration = IosAttestationConfiguration(
                applications = listOf(
                    IosAttestationConfiguration.AppData(
                        teamIdentifier = "9CYHJNG644",
                        bundleIdentifier = "at.asitplus.attestation-client",
                        sandbox = false
                    )
                ),
                iosVersion = IosAttestationConfiguration.OsVersions(
                    semVer = "16",
                    buildNumber = "0A0"
                ) //optional, use SemVer notation and large hex number to ignore build number
            ),
            clock = FixedTimeClock(Instant.parse("2023-04-13T14:03:00Z")), //optional
            verificationTimeOffset = Duration.ZERO //optional
        )


        "Android" - {
            "Attestation generic" {
                //For android, this is always key attestation
                service.verifyAttestation(nokiaX10KeyMasterGood.attestationProof, nokiaX10KeyMasterGood.challenge)
                    .apply {
                        shouldBeInstanceOf<AttestationResult.Android>().apply {
                            attestationCertificate.encoded shouldBe nokiaX10KeyMasterGood.attestationProof.first()
                            attestationRecord.attestationChallenge()
                                .toByteArray() shouldBe nokiaX10KeyMasterGood.challenge
                            attestationRecord.attestationSecurityLevel() shouldBeIn listOf(
                                ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT,
                                ParsedAttestationRecord.SecurityLevel.STRONG_BOX
                            )
                        }
                    }
            }

            "Key Attestation" - {
                //same same, but different

                "Platform-Independent" {
                    service.verifyKeyAttestation(
                        nokiaX10KeyMasterGood.attestationProof,
                        nokiaX10KeyMasterGood.challenge,
                        nokiaX10KeyMasterGood.publicKey!!
                    ).apply {
                        shouldBeInstanceOf<KeyAttestation<ECPublicKey>>().apply {
                            isSuccess.shouldBeTrue()
                            attestedPublicKey!!.encoded shouldBe nokiaX10KeyMasterGood.publicKey!!.encoded
                            details.shouldBeInstanceOf<AttestationResult.Android>().apply {
                                attestationCertificate.encoded shouldBe nokiaX10KeyMasterGood.attestationProof.first()
                                attestationRecord.attestationChallenge()
                                    .toByteArray() shouldBe nokiaX10KeyMasterGood.challenge
                                attestationRecord.attestationSecurityLevel() shouldBeIn listOf(
                                    ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT,
                                    ParsedAttestationRecord.SecurityLevel.STRONG_BOX
                                )
                            }
                        }
                    }
                }

                "Android-Specific" {
                    service.android.verifyKeyAttestation(
                        nokiaX10KeyMasterGood.attestationCertChain,
                        nokiaX10KeyMasterGood.challenge,
                    ).apply {
                        shouldBeInstanceOf<KeyAttestation<ECPublicKey>>().apply {
                            isSuccess.shouldBeTrue()
                            attestedPublicKey!!.encoded shouldBe nokiaX10KeyMasterGood.publicKey!!.encoded
                            details.shouldBeInstanceOf<AttestationResult.Android>().apply {
                                attestationCertificate.encoded shouldBe nokiaX10KeyMasterGood.attestationProof.first()
                                attestationRecord.attestationChallenge()
                                    .toByteArray() shouldBe nokiaX10KeyMasterGood.challenge
                                attestationRecord.attestationSecurityLevel() shouldBeIn listOf(
                                    ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT,
                                    ParsedAttestationRecord.SecurityLevel.STRONG_BOX
                                )
                            }
                        }
                    }
                }
            }
        }

        "iOS" - {
            "App Attestation" - {
                "Platform-Independent" {
                    //Only verify App Attestation, so no assertion is part of the proof. Hence, only a single element
                    service.verifyAttestation(listOf(ios16.attestationProof[0]), ios16.challenge).apply {
                        shouldBeInstanceOf<AttestationResult.IOS>()
                    }
                }
                "iOS-Specific" {
                    //use the ios-specific function
                    service.ios.verifyAppAttestation(ios16.attestationProof[0], ios16.challenge).apply {
                        shouldBeInstanceOf<AttestationResult.IOS>()
                    }
                }
            }

            "Attestation with assertion" - {
                "Platform-Independent " {
                    //verifies that computing `clientData` was the first asserted operation performed after attesting the app
                    service.verifyAttestation(ios16.attestationProof, ios16.challenge, ios16.publicKey!!.encoded)
                        .apply {
                            shouldBeInstanceOf<AttestationResult.IOS>().apply {
                                clientData shouldBe ios16.publicKey!!.encoded //now we know that the app produced `clientData` as we intended
                                //in this case, this produced data is the encoded public key
                            }
                        }
                }

                "iOS-Specific" - {
                    "Assertion implicitly created immediately" {
                        //verifies that computing `clientData` was the first asserted operation performed after attesting the app
                        service.ios.verifyAssertion(
                            attestationObject = ios16.attestationProof[0],
                            assertionFromDevice = ios16.attestationProof[1],
                            referenceClientData = ios16.publicKey!!.encoded,
                            challenge = ios16.challenge
                        ).apply {
                            shouldBeInstanceOf<AttestationResult.IOS>().apply {
                                clientData shouldBe ios16.publicKey!!.encoded //now we know that the app produced `clientData` as we intended
                                //in this case, this produced data is the encoded public key
                            }
                        }
                    }

                    "Assertion explicitly created immediately" {
                        //verifies that computing `clientData` was the first asserted operation performed after attesting the app
                        service.ios.verifyAssertion(
                            attestationObject = ios16.attestationProof[0],
                            assertionFromDevice = ios16.attestationProof[1],
                            referenceClientData = ios16.publicKey!!.encoded,
                            challenge = ios16.challenge,
                            counter = 0L //explicitly specify counter
                        ).apply {
                            shouldBeInstanceOf<AttestationResult.IOS>().apply {
                                clientData shouldBe ios16.publicKey!!.encoded //now we know that the app produced `clientData` as we intended
                                //in this case, this produced data is the encoded public key
                            }
                        }
                    }
                }
            }

            "Key Attestation Emulation for iOS through Platform-independent API" {
                service.verifyKeyAttestation(
                    ios16.attestationProof,
                    ios16.challenge,
                    ios16.publicKey!!
                ).apply {
                    shouldBeInstanceOf<KeyAttestation<ECPublicKey>>().apply {
                        isSuccess.shouldBeTrue()
                        attestedPublicKey!!.encoded shouldBe ios16.publicKey!!.encoded
                        details.shouldBeInstanceOf<AttestationResult.IOS>().apply {
                            clientData shouldBe ios16.publicKey!!.encoded
                        }
                    }
                }
            }
        }
    }
