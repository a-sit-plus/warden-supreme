@file:OptIn(ExperimentalStdlibApi::class)

package examples.docs.generator

import at.asitplus.attestation.android.AttestationKeyDescription.SecurityLevel
import at.asitplus.attestation.android.AuthorizationList
import at.asitplus.attestation.generator.AndroidAttestationIssuer
import at.asitplus.attestation.generator.GeneratorConfig
import at.asitplus.attestation.generator.Provisioning
import at.asitplus.attestation.generator.attestationSpec
import at.asitplus.attestation.generator.issuerSpec
import at.asitplus.attestation.generator.mangle
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.matrixConfig
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import kotlinx.datetime.Month
import java.io.File
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * Writes the generator CLI's example configurations into the documentation, and proves they work: each
 * one is decoded from its own JSON again and every attestation in it is actually issued.
 *
 * The timestamps are fixed, so the generated files only change when the examples do.
 */
val GeneratorConfigExampleGenerator by matrixSuite(matrixConfig { execution = ExecutionMode.Sequential }) {

    val docs = File("../../docs/docs/examples").also { it.mkdirs() }
    val issuedAt = Instant.parse("2026-01-15T09:30:00Z")
    val createdAt = Instant.parse("2026-01-15T09:35:00Z")

    /** An unknown property, of the kind devices emit and a verifier has to survive. */
    fun unknownProperty(): Asn1Element = Asn1.ExplicitlyTagged(9999uL) { +Asn1.Int(1) }

    val examples = linkedMapOf(
        // 1. The smallest configuration that does something: everything else is a default.
        "generator-minimal" to GeneratorConfig(
            issuer = issuerSpec { this.issuedAt = issuedAt },
            attestations = listOf(attestationSpec { this.createdAt = createdAt }),
            outputDirectory = "attestations",
        ),

        // 2. What a TEE-backed Android device actually attests to.
        "generator-tee-factory" to GeneratorConfig(
            issuer = issuerSpec {
                factoryProvisioned(SecurityLevel.TRUSTED_ENVIRONMENT)
                this.issuedAt = issuedAt
            },
            attestations = listOf(
                attestationSpec {
                    this.createdAt = createdAt
                    securityLevel = SecurityLevel.TRUSTED_ENVIRONMENT
                    nonce = "server-challenge".encodeToByteArray()
                    softwareEnforced = AuthorizationList(
                        creationDateTime = AuthorizationList.CreationDateTime(createdAt),
                        attestationApplicationId = AuthorizationList.AttestationApplicationId(
                            packageInfos = setOf(
                                AuthorizationList.AttestationPackageInfo(
                                    "at.asitplus.attestation_client",
                                    version = 1u
                                )
                            ),
                            signatureDigests = setOf(ByteArray(32) { 0x11 }),
                        ),
                    )
                    hardwareEnforced = AuthorizationList(
                        purpose = setOf(AuthorizationList.KeyPurpose.SIGN),
                        algorithm = AuthorizationList.Algorithm.EC,
                        keySize = AuthorizationList.KeySize(BitLength(256u)),
                        ecCurve = AuthorizationList.ECCurve.P_256,
                        noAuthRequired = AuthorizationList.NoAuthRequired,
                        origin = AuthorizationList.Origin.GENERATED,
                        rootOfTrust = AuthorizationList.RootOfTrust(
                            verifiedBootKeyDigest = ByteArray(32) { 0x22 },
                            deviceLocked = true,
                            verifiedBootState = AuthorizationList.RootOfTrust.VerifiedBootState.Verified,
                            verifiedBootHash = ByteArray(32) { 0x33 },
                        ),
                        osVersion = AuthorizationList.OsVersion(14u, 0u, 0u),
                        osPatchLevel = AuthorizationList.OsPatchLevel(2026u, Month.AUGUST),
                    )
                }
            ),
            outputDirectory = "attestations/tee",
        ),

        // 3. StrongBox, provisioned remotely: a different chain shape, stated in the subject names.
        "generator-strongbox-rkp" to GeneratorConfig(
            issuer = issuerSpec {
                rkp(SecurityLevel.STRONGBOX)
                this.issuedAt = issuedAt
                validity = 30.minutes
            },
            attestations = listOf(
                attestationSpec {
                    this.createdAt = createdAt
                    securityLevel = SecurityLevel.STRONGBOX
                    nonce = "server-challenge".encodeToByteArray()
                    hardwareEnforced = AuthorizationList(
                        purpose = setOf(AuthorizationList.KeyPurpose.SIGN),
                        algorithm = AuthorizationList.Algorithm.EC,
                        ecCurve = AuthorizationList.ECCurve.P_256,
                        deviceUniqueAttestation = AuthorizationList.DeviceUniqueAttestation,
                        moduleHash = AuthorizationList.ModuleHash(ByteArray(32) { 0x44 }),
                    )
                }
            ),
            outputDirectory = "attestations/strongbox-rkp",
        ),

        // 4. Two vectors that must be rejected: a property that is valid ASN.1 but wrong, and a
        //    device that failed verified boot while emitting a property outside the schema.
        "generator-negative-vectors" to GeneratorConfig(
            issuer = issuerSpec { this.issuedAt = issuedAt },
            attestations = listOf(
                attestationSpec {
                    this.createdAt = createdAt
                    nonce = "server-challenge".encodeToByteArray()
                    hardwareEnforced = AuthorizationList(algorithm = AuthorizationList.Algorithm.EC)
                        .mangle(AuthorizationList.KeySize, "a30402020080")
                },
                attestationSpec {
                    this.createdAt = createdAt
                    nonce = "server-challenge".encodeToByteArray()
                    hardwareEnforced = AuthorizationList(
                        algorithm = AuthorizationList.Algorithm.EC,
                        rootOfTrust = AuthorizationList.RootOfTrust(
                            verifiedBootKeyDigest = ByteArray(32) { 0x22 },
                            deviceLocked = false,
                            verifiedBootState = AuthorizationList.RootOfTrust.VerifiedBootState.Unverified,
                            verifiedBootHash = ByteArray(32) { 0x33 },
                        ),
                        trailingProperties = listOf(unknownProperty()),
                    )
                }
            ),
            outputDirectory = "attestations/negative",
        ),
    )

    examples.forEach { (name, config) ->
        "$name.json" {
            val json = config.toJson()

            withClue("the configuration in the documentation must be one the CLI accepts") {
                val decoded = GeneratorConfig.fromJson(json)
                decoded.issuer shouldBe config.issuer
                decoded.toJson() shouldBe json
                // Compared as ASN.1: a deliberately mangled property decodes back into a typed one
                // when it happens to be valid, and the bytes are what the CLI writes either way.
                decoded.attestations.map { it.keyDescription.encodeToTlv().derEncoded.toHexString() } shouldBe
                        config.attestations.map { it.keyDescription.encodeToTlv().derEncoded.toHexString() }
                val issuer = AndroidAttestationIssuer.from(decoded.issuer)
                decoded.attestations.forEach { attestation ->
                    val issued = issuer.issue(attestation)
                    issued.certificateChain.size shouldBe
                            if (decoded.issuer.provisioning == Provisioning.RKP) 5 else 4
                }
            }

            File(docs, "$name.json").writeText(json + "\n")
        }
    }
}
