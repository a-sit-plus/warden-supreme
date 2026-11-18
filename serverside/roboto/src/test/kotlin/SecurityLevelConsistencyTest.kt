package at.asitplus.attestation.android

import at.asitplus.attestation.android.AttestationKeyDescription.SecurityLevel
import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.attestation.generator.Provisioning
import at.asitplus.attestation.generator.androidAttestationIssuer
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.testballoon.matrix.matrixSuite
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

    data class Claim(
        val name: String, val issuer: SecurityLevel, val attestation: SecurityLevel, val keyMint: SecurityLevel,
        val acceptedWithoutRequirement: Boolean = true, val acceptedWithRequirement: Boolean = false,
        val acceptedWhenUnderclaimAllowed: Boolean = acceptedWithoutRequirement,
    )
    val claims = listOf(
        Claim("TEE baseline", tee, tee, tee),
        Claim("genuine StrongBox", strongBox, strongBox, strongBox, acceptedWithRequirement = true),
        Claim("TEE chain with both leaf levels claiming StrongBox", tee, strongBox, strongBox, acceptedWithoutRequirement = false),
        Claim("TEE chain with only attestation claiming StrongBox", tee, strongBox, tee, acceptedWithoutRequirement = false),
        Claim("TEE chain with only KeyMint claiming StrongBox", tee, tee, strongBox, acceptedWithoutRequirement = false),
        Claim("StrongBox chain with both leaf levels claiming TEE", strongBox, tee, tee,
            acceptedWithoutRequirement = false, acceptedWhenUnderclaimAllowed = true),
        Claim("StrongBox chain with only attestation claiming TEE", strongBox, tee, strongBox,
            acceptedWithoutRequirement = false, acceptedWhenUnderclaimAllowed = true),
        Claim("StrongBox chain with only KeyMint claiming TEE", strongBox, strongBox, tee,
            acceptedWithoutRequirement = false, acceptedWhenUnderclaimAllowed = true),
        Claim("StrongBox chain with software leaf levels", strongBox, software, software, acceptedWithoutRequirement = false),
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
            val chain: CertificateChain = issuers.getValue(claim.issuer).issue {
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
                hardwareEnforced = AuthorizationList(rootOfTrust = AuthorizationList.RootOfTrust(
                    verifiedBootKeyDigest = ByteArray(32) { 2 }, deviceLocked = true,
                    verifiedBootState = AuthorizationList.RootOfTrust.VerifiedBootState.Verified,
                    verifiedBootHash = ByteArray(32) { 3 },
                ))
            }.certificateChain
            data("supremeParser", listOf(false, true)) - { supreme ->
                data("requireStrongBox", listOf(false, true)) - { required ->
                    data("allowTeeSecurityLevelForStrongbox", listOf(false, true)) test { allowUnderclaim ->
                        val checker = Roboto(AndroidAttestationConfiguration(
                            applications = listOf(AndroidAttestationConfiguration.AppData("security.level.test", setOf(fingerprint))),
                            hardwareTrustedRoots = setOf(TrustedRoot.Certificate(chain.last())),
                            androidVersion = null, patchLevel = null, revocation = emptyList(),
                            supremeParser = supreme, requireStrongBox = required, ignoreLeafValidity = false,
                            allowTeeSecurityLevelForStrongbox = allowUnderclaim,
                        ))
                        val accepted = when {
                            required -> claim.acceptedWithRequirement
                            allowUnderclaim -> claim.acceptedWhenUnderclaimAllowed
                            else -> claim.acceptedWithoutRequirement
                        }
                        if (!accepted) {
                            shouldThrow<AttestationValueException> {
                                checker.verify(chain, issuedAt + 10.seconds, challenge).getOrThrow()
                            }.reason shouldBe AttestationValueException.Reason.SEC_LEVEL
                        } else {
                            checker.verify(chain, issuedAt + 10.seconds, challenge).getOrThrow() shouldBe chain
                        }
                    }
                }
            }
        }
    }
}
