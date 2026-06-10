package at.asitplus.attestation

import at.asitplus.attestation.data.AttestationData
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldNotBeInstanceOf
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds

val TemporalOffsetTest by matrixSuite {

    val exactStartOfValidity: Map<String, AttestationData> = mapOf(
        "iOS" to ios16,
        "KeyMint 200" to pixel6KeyMint200Good
    )


    "Exact Time of Validity" - {
        data("attestations", exactStartOfValidity.toList(), nameFn = { _, (name, _) -> name }) test { (_, it) ->
            val attestationService = attestationService(timeSource = FixedTimeClock(it.verificationDate))
            attestationService.verifyAttestation(
                it.attestationProof,
                it.challenge
            ).apply {
                shouldNotBeInstanceOf<AttestationResult.Error>()
                WardenDebugAttestationStatement.deserializeCompact(
                    attestationService.collectDebugInfo(it.attestationProof, it.challenge).serializeCompact()
                ).replay() shouldBe this
            }
        }
    }

    "Exact Time of Validity + 1D" - {
        data("attestations", exactStartOfValidity.toList(), nameFn = { _, (name, _) -> name }) test { (_, it) ->
            val attestationService = attestationService(
                timeSource = FixedTimeClock(it.verificationDate),
                offset = 1.days,
                androidAttestationStatementValidity = 1.days + 1.seconds,
                iosAttestationStatementValidity = 1.days + 1.seconds,
            )
            attestationService.verifyAttestation(
                it.attestationProof,
                it.challenge,
            ).apply {
                shouldNotBeInstanceOf<AttestationResult.Error>()
                WardenDebugAttestationStatement.deserializeCompact(
                    attestationService.collectDebugInfo(it.attestationProof, it.challenge).serializeCompact()
                ).replay() shouldBe this
            }
        }
    }

    "Exact Time of Validity - 1D" - {
        data("attestations", listOf(pixel6KeyMint200Good), nameFn = { _, it -> it.name }) test {
            val attestationService = attestationService(
                timeSource = FixedTimeClock(it.verificationDate),
                offset = (-1).days,
                androidSW = true
            )
            attestationService.verifyAttestation(
                it.attestationProof,
                it.challenge,
            ).apply {
                shouldBeInstanceOf<AttestationResult.Error>()
                    .cause.shouldBeInstanceOf<AttestationException.Certificate.Time>()
                WardenDebugAttestationStatement.deserializeCompact(
                    attestationService.collectDebugInfo(it.attestationProof, it.challenge).serializeCompact()
                ).replay() shouldBe this

            }
        }
    }

    "KeyMint eternal leaves - 1D" - {
        data("validity", listOf("eternal" to true, "expiring" to false), nameFn = { _, (name, _) -> name }) test {
            val attestationService = attestationService(
                timeSource = FixedTimeClock(pixel6KeyMint200Good.verificationDate),
                offset = (-1).days,
                androidSW = true
            )
            attestationService.verifyAttestation(
                pixel6KeyMint200Good.attestationProof,
                pixel6KeyMint200Good.challenge,
            ).apply {
                shouldBeInstanceOf<AttestationResult.Error>()
                    .cause.shouldBeInstanceOf<AttestationException.Certificate.Time>()
                WardenDebugAttestationStatement.deserializeCompact(
                    attestationService.collectDebugInfo(
                        pixel6KeyMint200Good.attestationProof,
                        pixel6KeyMint200Good.challenge
                    ).serializeCompact()
                ).replay() shouldBe this
            }
        }
    }

    "iOS Temporal Offset Strict Fail" - {
        data("offset", listOf(1.days, -1.days), nameFn = { _, value -> value.toIsoString() }) test { offset ->
            val attestationService = attestationService(
                timeSource = FixedTimeClock(ios16.verificationDate),
                offset = offset,
                iosAttestationStatementValidity = 23.hours,
                androidAttestationStatementValidity = 23.hours
            )
            attestationService.verifyAttestation(
                ios16.attestationProof,
                ios16.challenge,
            ).apply {
                shouldBeInstanceOf<AttestationResult.Error>()
                cause.shouldBeInstanceOf<AttestationException.Content>()
                cause.cause.shouldBeInstanceOf<IosAttestationException>()
                (cause.cause as IosAttestationException).reason shouldBe IosAttestationException.Reason.STATEMENT_TIME

                WardenDebugAttestationStatement.deserializeCompact(
                    attestationService.collectDebugInfo(ios16.attestationProof, ios16.challenge).serializeCompact()
                ).replay() shouldBe this
            }
        }

    }
}
