package examples.docs.generator

import at.asitplus.attestation.android.AttestationKeyDescription
import at.asitplus.attestation.android.AuthorizationList
import at.asitplus.attestation.android.androidAttestationExtension
import at.asitplus.attestation.generator.GeneratorConfig
import at.asitplus.attestation.generator.androidAttestationIssuer
import at.asitplus.attestation.generator.mangle
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.datetime.Month
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

/**
 * The samples shown in the documentation. They are tests, so the documentation cannot rot: every
 * snippet below is compiled and executed on every build.
 */
val GeneratorDslExamples by matrixSuite {

    "issuing an attestation" {
// --8<-- [start:generator-issue]
val issuer = androidAttestationIssuer {
    /*(1)!*/factoryProvisioned(AttestationKeyDescription.SecurityLevel.TRUSTED_ENVIRONMENT)
}

val attestation = issuer.issue {
    /*(2)!*/nonce = "server-challenge".encodeToByteArray()
    hardwareEnforced = AuthorizationList(
        purpose = setOf(AuthorizationList.KeyPurpose.SIGN),
        algorithm = AuthorizationList.Algorithm.EC,
        ecCurve = AuthorizationList.ECCurve.P_256,
        noAuthRequired = AuthorizationList.NoAuthRequired,
        origin = AuthorizationList.Origin.GENERATED,
    )
}

/*(3)!*/val chain = attestation.certificateChain
/*(4)!*/val attestedKey = attestation.leafSigner
// --8<-- [end:generator-issue]
        chain.size shouldBe 4
        attestedKey.publicKey shouldBe attestation.leafCertificate.decodedPublicKey.getOrThrow()
        requireNotNull(attestation.leafCertificate.androidAttestationExtension)
            .hardwareEnforced.algorithm?.getOrThrow() shouldBe AuthorizationList.Algorithm.EC
    }

    "a complete device statement" {
        val issuer = androidAttestationIssuer { factoryProvisioned() }
// --8<-- [start:generator-statement]
val attestation = issuer.issue {
    /*(1)!*/attestationVersion = 400
    keyMintVersion = 400
    securityLevel = AttestationKeyDescription.SecurityLevel.TRUSTED_ENVIRONMENT
    nonce = "server-challenge".encodeToByteArray()

    /*(2)!*/softwareEnforced = AuthorizationList(
        creationDateTime = AuthorizationList.CreationDateTime(createdAt),
        attestationApplicationId = AuthorizationList.AttestationApplicationId(
            packageInfos = setOf(
                AuthorizationList.AttestationPackageInfo("at.asitplus.attestation_client", version = 1u)
            ),
            signatureDigests = setOf(ByteArray(32) { 0x11 }),
        ),
    )

    /*(3)!*/hardwareEnforced = AuthorizationList(
        purpose = setOf(AuthorizationList.KeyPurpose.SIGN),
        algorithm = AuthorizationList.Algorithm.EC,
        keySize = AuthorizationList.KeySize(BitLength(256u)),
        ecCurve = AuthorizationList.ECCurve.P_256,
        noAuthRequired = AuthorizationList.NoAuthRequired,
        origin = AuthorizationList.Origin.GENERATED,
        /*(4)!*/rootOfTrust = AuthorizationList.RootOfTrust(
            verifiedBootKeyDigest = ByteArray(32) { 0x22 },
            deviceLocked = true,
            verifiedBootState = AuthorizationList.RootOfTrust.VerifiedBootState.Verified,
            verifiedBootHash = ByteArray(32) { 0x33 },
        ),
        osVersion = AuthorizationList.OsVersion(14u, 0u, 0u),
        osPatchLevel = AuthorizationList.OsPatchLevel(2026u, Month.AUGUST),
    )
}
// --8<-- [end:generator-statement]
        val parsed = requireNotNull(attestation.leafCertificate.androidAttestationExtension)
        parsed.hardwareEnforced.rootOfTrust?.getOrThrow()?.deviceLocked shouldBe true
        parsed.softwareEnforced.attestationApplicationId?.getOrThrow()
            ?.packageInfos?.single()?.packageName shouldBe "at.asitplus.attestation_client"
    }

    "remote key provisioning" {
// --8<-- [start:generator-rkp]
val issuer = androidAttestationIssuer {
    /*(1)!*/rkp(AttestationKeyDescription.SecurityLevel.STRONGBOX)
}

val attestation = issuer.issue {
    securityLevel = AttestationKeyDescription.SecurityLevel.STRONGBOX
    nonce = "server-challenge".encodeToByteArray()
}
/*(2)!*/val chain = attestation.certificateChain
// --8<-- [end:generator-rkp]
        chain.size shouldBe 5
        requireNotNull(attestation.leafCertificate.androidAttestationExtension)
            .keyMintSecurityLevel shouldBe AttestationKeyDescription.SecurityLevel.STRONGBOX
    }

    "one trust anchor, many attestations" {
// --8<-- [start:generator-anchor]
/*(1)!*/val issuer = androidAttestationIssuer {
    factoryProvisioned()
    /*(2)!*/issuedAt = Instant.parse("2026-01-15T09:30:00Z")
    validity = 90.days
}

/*(3)!*/val trustAnchor = issuer.rootCertificate

val attestations = List(3) { index ->
    issuer.issue { nonce = "challenge-$index".encodeToByteArray() }
}
// --8<-- [end:generator-anchor]
        attestations.map { it.rootCertificate }.distinct() shouldBe listOf(trustAnchor)
    }

    "a negative test vector" {
        val issuer = androidAttestationIssuer { factoryProvisioned() }
// --8<-- [start:generator-mangled]
val attestation = issuer.issue {
    hardwareEnforced = AuthorizationList(algorithm = AuthorizationList.Algorithm.EC)
        /*(1)!*/.mangle(AuthorizationList.KeySize, "a30402020080")
}
// --8<-- [end:generator-mangled]
        val parsed = requireNotNull(attestation.leafCertificate.androidAttestationExtension)
        parsed.hardwareEnforced.keySize?.isFailure() shouldBe false // valid ASN.1, wrong by intent
    }

    "handing a configuration to the CLI" {
// --8<-- [start:generator-config]
val issuer = androidAttestationIssuer { factoryProvisioned() }

/*(1)!*/val json = issuer.configuration(
    attestations = listOf(
        /*(2)!*/at.asitplus.attestation.generator.attestationSpec {
            nonce = "server-challenge".encodeToByteArray()
        }
    ),
    outputDirectory = "build/attestations",
).toJson()
// --8<-- [end:generator-config]
        val decoded = GeneratorConfig.fromJson(json)
        /*(3)!*/requireNotNull(decoded.issuer.root) // the generated root is exported, so runs repeat
        decoded.attestations.single().keyDescription.attestationChallenge
            .decodeToString() shouldBe "server-challenge"
    }
}
