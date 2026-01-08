import at.asitplus.attestation.*
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldNotBeInstanceOf
import kotlin.time.toKotlinInstant

val singlePlatform by testSuite {

    "iOS-only" - {
        iosGood.forEach { recordedAttestation ->
            recordedAttestation.name - {
                Makoto(
                    iosAttestationConfiguration = IosAttestationConfiguration(
                        IosAttestationConfiguration.AppData(
                            DEFAULT_IOS_ATTESTATION_CFG.applications.first().teamIdentifier,
                            recordedAttestation.packageOverride
                                ?: DEFAULT_IOS_ATTESTATION_CFG.applications.first().bundleIdentifier,
                            recordedAttestation.isProductionOverride?.not()
                                ?: false
                        )
                    ),
                    clock = FixedTimeClock(
                        recordedAttestation.verificationDate.toInstant().toKotlinInstant(),
                    )
                ).apply {
                    "with iOS" {
                        verifyAttestation(
                            recordedAttestation.attestationProof,
                            recordedAttestation.challenge
                        ).apply {
                            also { println(it) }
                            shouldNotBeInstanceOf<AttestationResult.Error>()
                        }
                        val dbg = collectDebugInfo(
                            recordedAttestation.attestationProof,
                            recordedAttestation.challenge
                        ).serializeCompact()
                        val replayGenericAttestation =
                            WardenDebugAttestationStatement.deserializeCompact(dbg)
                                .replayGenericAttestation()
                        replayGenericAttestation shouldBe WardenDebugAttestationStatement.deserializeCompact(
                            dbg
                        )
                            .replay()
                        replayGenericAttestation
                            .shouldNotBeInstanceOf<AttestationResult.Error>()

                    }

                    "with Android" - {
                        androidGood.forEach { recordedAttestation ->
                            recordedAttestation.name {
                                verifyAttestation(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).apply {
                                    also { println(it) }
                                    shouldBeInstanceOf<AttestationResult.Error>()
                                    cause.shouldBeInstanceOf<AttestationException.Configuration>()
                                    cause.platform shouldBe Platform.ANDROID
                                }
                                val dbg = collectDebugInfo(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).serializeCompact()
                                val replayGenericAttestation =
                                    WardenDebugAttestationStatement.deserializeCompact(dbg)
                                        .replayGenericAttestation()
                                replayGenericAttestation shouldBe WardenDebugAttestationStatement.deserializeCompact(
                                    dbg
                                )
                                    .replay()
                                replayGenericAttestation
                                    .shouldBeInstanceOf<AttestationResult.Error>().apply {
                                        cause.shouldBeInstanceOf<AttestationException.Configuration>()
                                        cause.platform shouldBe Platform.ANDROID
                                    }
                            }
                        }
                    }
                }
            }
        }
    }
    "Android-only" - {
        androidGood.forEach { recordedAttestation ->
            recordedAttestation.name - {
                Makoto(
                    androidAttestationConfiguration = AndroidAttestationConfiguration(
                        singleApp = AndroidAttestationConfiguration.AppData(
                            recordedAttestation.packageOverride ?: ANDROID_PACKAGE_NAME,
                            ANDROID_SIGNATURE_DIGESTS
                        )
                    ),
                    clock = FixedTimeClock(
                        recordedAttestation.verificationDate.toInstant().toKotlinInstant(),
                    )
                ).apply {
                    "with Android" {
                        verifyAttestation(
                            recordedAttestation.attestationProof,
                            recordedAttestation.challenge
                        ).apply {
                            also { println(it) }
                            shouldNotBeInstanceOf<AttestationResult.Error>()
                        }
                        val dbg = collectDebugInfo(
                            recordedAttestation.attestationProof,
                            recordedAttestation.challenge
                        ).serializeCompact()
                        val replayGenericAttestation =
                            WardenDebugAttestationStatement.deserializeCompact(dbg)
                                .replayGenericAttestation()
                        replayGenericAttestation shouldBe WardenDebugAttestationStatement.deserializeCompact(
                            dbg
                        )
                            .replay()
                        replayGenericAttestation
                            .shouldNotBeInstanceOf<AttestationResult.Error>()

                    }

                    "with iOS" - {
                        iosGood.forEach { recordedAttestation ->
                            recordedAttestation.name {
                                verifyAttestation(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).apply {
                                    also { println(it) }
                                    shouldBeInstanceOf<AttestationResult.Error>()
                                    cause.shouldBeInstanceOf<AttestationException.Configuration>()
                                    cause.platform shouldBe Platform.IOS
                                }
                                val dbg = collectDebugInfo(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).serializeCompact()
                                val replayGenericAttestation =
                                    WardenDebugAttestationStatement.deserializeCompact(dbg)
                                        .replayGenericAttestation()
                                replayGenericAttestation shouldBe WardenDebugAttestationStatement.deserializeCompact(
                                    dbg
                                )
                                    .replay()
                                replayGenericAttestation
                                    .shouldBeInstanceOf<AttestationResult.Error>().apply {
                                        cause.shouldBeInstanceOf<AttestationException.Configuration>()
                                        cause.platform shouldBe Platform.IOS
                                    }
                            }
                        }
                    }
                }
            }
        }
    }
}