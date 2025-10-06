
package at.asitplus.attestation

import at.asitplus.attestation.data.AttestationData
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldNotBeInstanceOf
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds

class TemporalOffsetTest : FreeSpec() {

    private val exactStartOfValidity: Map<String, AttestationData> = mapOf(
        "iOS" to ios16,
        "KeyMint 200" to pixel6KeyMint200Good
    )

    init {
        "Exact Time of Validity" - {
            withData(exactStartOfValidity) {
                val attestationService = attestationService(timeSource = FixedTimeClock(it.verificationDate.time))
                attestationService.verifyAttestation(
                    it.attestationProof,
                    it.challenge
                ).apply {
                    shouldNotBeInstanceOf<AttestationResult.Error>()
                    WardenDebugAttestationStatement.deserializeCompact(
                        attestationService.collectDebugInfo(it.attestationProof, it.challenge).serializeCompact()
                    ).replaySmart(ignoreProxy = false) shouldBe this
                }
            }
        }

        "Exact Time of Validity + 1D" - {
            withData(exactStartOfValidity) {
                val attestationService = attestationService(
                    timeSource = FixedTimeClock(it.verificationDate.time),
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
                    ).replaySmart(ignoreProxy = false) shouldBe this
                }
            }
        }

        "Exact Time of Validity - 1D" - {
            withData(mapOf("KeyMint 200" to pixel6KeyMint200Good)) {
                val attestationService = attestationService(
                    timeSource = FixedTimeClock(it.verificationDate.time),
                    offset = (-1).days,
                    androidN = true, androidSW = true
                )
                attestationService.verifyAttestation(
                    it.attestationProof,
                    it.challenge,
                ).apply {
                    shouldBeInstanceOf<AttestationResult.Error>()
                        .cause.shouldBeInstanceOf<AttestationException.Certificate.Time>()
                    WardenDebugAttestationStatement.deserializeCompact(
                        attestationService.collectDebugInfo(it.attestationProof, it.challenge).serializeCompact()
                    ).replaySmart(ignoreProxy = false) shouldBe this

                }
            }
        }

        "KeyMint eternal leaves - 1D" - {
            withData("eternal" to true, "expiring" to false) {
                val attestationService = attestationService(
                    timeSource = FixedTimeClock(pixel6KeyMint200Good.verificationDate.time),
                    offset = (-1).days,
                    androidN = true, androidSW = true
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
                    ).replaySmart(ignoreProxy = false) shouldBe this
                }
            }
        }

        "iOS Temporal Offset Strict Fail" - {
            withData(nameFn = { it.toIsoString() }, 1.days, -1.days) { offset ->
                val attestationService = attestationService(
                    timeSource = FixedTimeClock(ios16.verificationDate.time),
                    offset = offset,
                    iosAttestationStatementValidity = 23.hours,
                    androidAttestationStatementValidity = 23.hours
                )
                attestationService.verifyAttestation(
                    ios16.attestationProof,
                    ios16.challenge,
                ).apply {
                    shouldBeInstanceOf<AttestationResult.Error>()
                    this.cause.shouldBeInstanceOf<AttestationException.Content>()
                    (this.cause as AttestationException.Content).cause.shouldBeInstanceOf<IosAttestationException>()
                    ((cause as AttestationException.Content).cause as IosAttestationException).reason shouldBe IosAttestationException.Reason.STATEMENT_TIME

                    WardenDebugAttestationStatement.deserializeCompact(
                        attestationService.collectDebugInfo(ios16.attestationProof, ios16.challenge).serializeCompact()
                    ).replaySmart(ignoreProxy = false) shouldBe this}
            }
        }
    }
}

