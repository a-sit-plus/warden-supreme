package at.asitplus.attestation.android

import at.asitplus.attestation.android.AttestationKeyDescription.SecurityLevel
import at.asitplus.attestation.android.engine.RtgAttestationEngine
import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.attestation.generator.Provisioning
import at.asitplus.attestation.generator.androidAttestationIssuer
import at.asitplus.testballoon.matrix.matrixSuite
import com.android.keyattestation.verifier.provider.KeyAttestationCertPath
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

val SecurityLevelConsistencyTest by matrixSuite {
    val issuedAt = Instant.parse("2025-01-10T00:00:00Z")
    val challenge = byteArrayOf(1, 2, 3, 4)
    val fingerprint = ByteArray(32) { 1 }
    val tee = SecurityLevel.TRUSTED_ENVIRONMENT
    val strongBox = SecurityLevel.STRONGBOX
    val software = SecurityLevel.SOFTWARE

    data class Rejection(val message: String, val expected: SecurityLevel, val actual: SecurityLevel)

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
        message shouldBe rejection.message
        expectedValue shouldBe rejection.expected
        actualValue shouldBe rejection.actual
    }

    fun chainRejection(expected: SecurityLevel, actual: SecurityLevel) = Rejection(
        "Attestation security level $actual does not match security level $expected inferred from certificate chain",
        expected,
        actual,
    )

    val teeRejectedByStrongBoxPolicy =
        Rejection("Attestation security level not StrongBox", strongBox, tee)
    val teeBaseline = Claim(
        "TEE baseline", issuer = tee, attestation = tee, keyMint = tee,
        strongBoxRejection = teeRejectedByStrongBoxPolicy,
    )
    val claims = listOf(
        teeBaseline,
        Claim("genuine StrongBox", strongBox, strongBox, strongBox),
        Claim(
            "TEE chain with both leaf levels claiming StrongBox", tee, strongBox, strongBox,
            chainRejection = chainRejection(tee, strongBox),
        ),
        Claim("TEE chain with only attestation claiming StrongBox", tee, strongBox, tee),
        Claim("TEE chain with only KeyMint claiming StrongBox", tee, tee, strongBox),
        Claim(
            "StrongBox chain with both leaf levels claiming TEE", strongBox, tee, tee,
            chainRejection = chainRejection(strongBox, tee), allowTeeUnderclaim = true,
            strongBoxRejection = teeRejectedByStrongBoxPolicy,
        ),
        Claim("StrongBox chain with only attestation claiming TEE", strongBox, tee, strongBox),
        Claim("StrongBox chain with only KeyMint claiming TEE", strongBox, strongBox, tee),
        Claim(
            "StrongBox chain with software leaf levels", strongBox, software, software,
            strongBoxRejection =
                Rejection("Attestation security level not StrongBox", strongBox, software),
            softwareRejection =
                Rejection("Attestation security level software", tee, software),
        ),
        Claim("StrongBox chain with only attestation claiming software", strongBox, software, strongBox),
        Claim("StrongBox chain with only KeyMint claiming software", strongBox, strongBox, software),
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
            val mismatchRejection = if (claim.attestation != claim.keyMint) {
                val attestationLevel = claim.attestation
                val keyMintLevel = claim.keyMint
                Rejection(
                    "Attestation security level $attestationLevel does not match Keymaster security level $keyMintLevel",
                    expected = keyMintLevel,
                    actual = attestationLevel,
                )
            } else null
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
            }.certificateChain
            val app = AndroidAttestationConfiguration.AppData("security.level.test", setOf(fingerprint))
            val configuration = AndroidAttestationConfiguration(
                applications = listOf(app),
                hardwareTrustedRoots = setOf(TrustedRoot.Certificate(chain.last())),
                androidVersion = null, patchLevel = null, revocation = emptyList(), ignoreLeafValidity = false,
            )
            if (provisioning == Provisioning.FACTORY && claim == teeBaseline) {
                "hardware fallback distinguishes an unknown chain level from SOFTWARE" {
                    val engine = RtgAttestationEngine.Hardware(configuration, ByteArray::contentEquals)
                    val chainLevel =
                        with(engine.certChainValidator) {chain.verify(issuedAt, setOf(TrustedRoot.Certificate(chain.last())), requireRKP = false)}
                    chainLevel.verdict.getOrThrow() shouldBe null
                    val record = with(engine) { chain.attestationRecord }
                    with(engine.HardwareEngine()) {
                        chainLevel.verdict.getOrThrow().coerce() shouldBe tee
                        software.coerce() shouldBe software
                        shouldThrow<AttestationValueException> {
                            verifySecurityLevel(software.coerce(), record, appOverride = null)
                        }.shouldMatch(chainRejection(software, tee))
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
                data(
                    "requireStrongBox",
                    policies,
                    nameFn = { "global=${it.global}, app=${it.appOverride}" }) - { policy ->
                    data("allowTeeSecurityLevelForStrongbox", listOf(false, true)) test { allowUnderclaim ->
                        val checker = Roboto(
                            configuration.copy(
                                applications = listOf(app.copy(requireStrongBoxOverride = policy.appOverride)),
                                supremeParser = supreme, requireStrongBox = policy.global,
                                allowTeeSecurityLevelForStrongbox = allowUnderclaim,
                            )
                        )
                        val rejection = mismatchRejection
                            ?: claim.chainRejection?.takeUnless { claim.allowTeeUnderclaim && allowUnderclaim }
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
