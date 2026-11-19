package at.asitplus.attestation.android

import at.asitplus.attestation.android.AttestationKeyDescription.SecurityLevel
import at.asitplus.attestation.android.engine.GeneralizedSecurityLevel
import at.asitplus.attestation.android.engine.GeneralizedSecurityLevel.SOFTWARE
import at.asitplus.attestation.android.engine.GeneralizedSecurityLevel.STRONGBOX
import at.asitplus.attestation.android.engine.GeneralizedSecurityLevel.TEE
import at.asitplus.attestation.android.engine.RtgAttestationEngine
import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.attestation.generator.Provisioning
import at.asitplus.attestation.generator.androidAttestationIssuer
import at.asitplus.signum.indispensable.toJcaCertificateBlocking
import at.asitplus.testballoon.matrix.matrixSuite
import com.android.keyattestation.verifier.provider.KeyAttestationCertPath
import com.google.android.attestation.ParsedAttestationRecord.SecurityLevel as ParsedSecurityLevel
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldStartWith
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

val SecurityLevelConsistencyTest by matrixSuite {
    val issuedAt = Instant.parse("2025-01-10T00:00:00Z")
    val challenge = byteArrayOf(1, 2, 3, 4)
    val fingerprint = ByteArray(32) { 1 }
    val tee = SecurityLevel.TRUSTED_ENVIRONMENT
    val strongBox = SecurityLevel.STRONGBOX
    val software = SecurityLevel.SOFTWARE
    val attestation = "Attestation"
    val keyMint = "Keymaster"

    data class Rejection(val field: String, val expected: Any, val actual: GeneralizedSecurityLevel)

    data class Claim(
        val name: String, val issuer: SecurityLevel, val attestation: SecurityLevel, val keyMint: SecurityLevel,
        val chainRejection: Rejection? = null,
        val allowTeeUnderclaim: Boolean = false,
        val strongBoxRejection: Rejection? = null,
        val softwareRejection: Rejection? = null,
    )

    data class StrongBoxPolicy(val global: Boolean, val appOverride: Boolean?, val expected: Boolean)

    fun AttestationValueException.shouldMatch(rejection: Rejection) {
        reason shouldBe AttestationValueException.Reason.SEC_LEVEL
        message.orEmpty() shouldStartWith "${rejection.field} security "
        expectedValue shouldBe rejection.expected
        actualValue shouldBe rejection.actual
    }

    val teeBaseline = Claim(
        "TEE baseline", tee, tee, tee,
        strongBoxRejection = Rejection(attestation, ParsedSecurityLevel.STRONG_BOX, TEE),
    )
    val claims = listOf(
        teeBaseline,
        Claim("genuine StrongBox", strongBox, strongBox, strongBox),
        Claim(
            "TEE chain with both leaf levels claiming StrongBox", tee, strongBox, strongBox,
            chainRejection = Rejection(attestation, TEE, STRONGBOX),
        ),
        Claim(
            "TEE chain with only attestation claiming StrongBox", tee, strongBox, tee,
            chainRejection = Rejection(attestation, TEE, STRONGBOX),
        ),
        Claim(
            "TEE chain with only KeyMint claiming StrongBox", tee, tee, strongBox,
            chainRejection = Rejection(keyMint, TEE, STRONGBOX),
        ),
        Claim(
            "StrongBox chain with both leaf levels claiming TEE", strongBox, tee, tee,
            chainRejection = Rejection(attestation, STRONGBOX, TEE), allowTeeUnderclaim = true,
            strongBoxRejection = Rejection(attestation, ParsedSecurityLevel.STRONG_BOX, TEE),
        ),
        Claim(
            "StrongBox chain with only attestation claiming TEE", strongBox, tee, strongBox,
            chainRejection = Rejection(attestation, STRONGBOX, TEE), allowTeeUnderclaim = true,
            strongBoxRejection = Rejection(attestation, ParsedSecurityLevel.STRONG_BOX, TEE),
        ),
        Claim(
            "StrongBox chain with only KeyMint claiming TEE", strongBox, strongBox, tee,
            chainRejection = Rejection(keyMint, STRONGBOX, TEE), allowTeeUnderclaim = true,
            strongBoxRejection = Rejection(keyMint, ParsedSecurityLevel.STRONG_BOX, TEE),
        ),
        Claim(
            "StrongBox chain with software leaf levels", strongBox, software, software,
            strongBoxRejection = Rejection(attestation, ParsedSecurityLevel.STRONG_BOX, SOFTWARE),
            softwareRejection = Rejection(attestation, ParsedSecurityLevel.TRUSTED_ENVIRONMENT, SOFTWARE),
        ),
        Claim(
            "StrongBox chain with only attestation claiming software", strongBox, software, strongBox,
            strongBoxRejection = Rejection(attestation, ParsedSecurityLevel.STRONG_BOX, SOFTWARE),
            softwareRejection = Rejection(attestation, ParsedSecurityLevel.TRUSTED_ENVIRONMENT, SOFTWARE),
        ),
        Claim(
            "StrongBox chain with only KeyMint claiming software", strongBox, strongBox, software,
            strongBoxRejection = Rejection(keyMint, ParsedSecurityLevel.STRONG_BOX, SOFTWARE),
            softwareRejection = Rejection(keyMint, ParsedSecurityLevel.TRUSTED_ENVIRONMENT, SOFTWARE),
        ),
    )

    data("provisioning", Provisioning.entries) - { provisioning ->
        val issuers = listOf(tee, strongBox).associateWith { level ->
            androidAttestationIssuer {
                this.issuedAt = issuedAt
                when (provisioning) {
                    Provisioning.FACTORY -> factoryProvisioned(level)
                    Provisioning.RKP -> rkp(level)
                }
            }
        }
        data("claims", claims, nameFn = { it.name }) - { claim ->
            val chain = issuers.getValue(claim.issuer).issue {
                createdAt = issuedAt
                nonce = challenge
                attestationSecurityLevel = claim.attestation
                keyMintSecurityLevel = claim.keyMint
                softwareEnforced = AuthorizationList(
                    creationDateTime = AuthorizationList.CreationDateTime(issuedAt),
                    attestationApplicationId = AuthorizationList.AttestationApplicationId(
                        packageInfos = setOf(AuthorizationList.AttestationPackageInfo("security.level.test", 1u)),
                        signatureDigests = setOf(fingerprint),
                    ),
                )
                hardwareEnforced = AuthorizationList(
                    rootOfTrust = AuthorizationList.RootOfTrust(
                        verifiedBootKeyDigest = ByteArray(32) { 2 }, deviceLocked = true,
                        verifiedBootState = AuthorizationList.RootOfTrust.VerifiedBootState.Verified,
                        verifiedBootHash = ByteArray(32) { 3 },
                    )
                )
            }.certificateChain.map { it.toJcaCertificateBlocking().getOrThrow() }
            val app = AndroidAttestationConfiguration.AppData("security.level.test", setOf(fingerprint))
            val configuration = AndroidAttestationConfiguration(
                applications = listOf(app),
                hardwareTrustedRoots = setOf(TrustedRoot.Certificate(chain.last())),
                androidVersion = null, patchLevel = null, revocation = emptyList(), ignoreLeafValidity = false,
            )
            if (provisioning == Provisioning.FACTORY && claim == teeBaseline) {
                "hardware fallback distinguishes an unknown chain level from SOFTWARE" {
                    val engine = RtgAttestationEngine.Hardware(configuration, ByteArray::contentEquals)
                    val chainLevel = with(engine.certChainValidator) { KeyAttestationCertPath(chain).generalizedSecurityLevel }
                    chainLevel shouldBe null
                    val record = with(engine) { chain.attestationRecord }
                    with(engine.HardwareEngine()) {
                        chainLevel.coerce() shouldBe TEE
                        SOFTWARE.coerce() shouldBe SOFTWARE
                        shouldThrow<AttestationValueException> {
                            verifySecurityLevel(SOFTWARE.coerce(), record, appOverride = null)
                        }.shouldMatch(Rejection(attestation, SOFTWARE, TEE))
                    }
                }
            }
            val policies = buildList {
                add(StrongBoxPolicy(global = false, appOverride = null, expected = false))
                add(StrongBoxPolicy(global = true, appOverride = null, expected = true))
                if (claim == teeBaseline) {
                    add(StrongBoxPolicy(global = false, appOverride = true, expected = true))
                    add(StrongBoxPolicy(global = true, appOverride = false, expected = false))
                }
            }
            data("supremeParser", listOf(false, true)) - { supreme ->
                data("requireStrongBox", policies, nameFn = { "global=${it.global}, app=${it.appOverride}" }) - { policy ->
                    data("allowTeeSecurityLevelForStrongbox", listOf(false, true)) test { allowUnderclaim ->
                        val checker = Roboto(
                            configuration.copy(
                                applications = listOf(app.copy(requireStrongBoxOverride = policy.appOverride)),
                                supremeParser = supreme, requireStrongBox = policy.global,
                                allowTeeSecurityLevelForStrongbox = allowUnderclaim,
                            )
                        )
                        val rejection = claim.chainRejection?.takeUnless { claim.allowTeeUnderclaim && allowUnderclaim }
                            ?: if (policy.expected) claim.strongBoxRejection else claim.softwareRejection
                        if (rejection != null) {
                            shouldThrow<AttestationValueException> {
                                checker.verify(chain, issuedAt + 10.seconds, challenge).getOrThrow()
                            }.shouldMatch(rejection)
                        } else {
                            checker.verify(chain, issuedAt + 10.seconds, challenge).getOrThrow() shouldBe chain
                        }
                    }
                }
            }
        }
    }
}
