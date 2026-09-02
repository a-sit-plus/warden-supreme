package at.asitplus.attestation.creator

import at.asitplus.attestation.android.AttestationKeyDescription
import at.asitplus.attestation.android.AttestationKeyDescription.SecurityLevel
import at.asitplus.attestation.android.AuthorizationList
import kotlinx.serialization.Serializable
import kotlin.time.Clock
import kotlin.time.Instant

/**
 * Everything needed to reproduce a set of fake Android key attestations, and the only model in this
 * module. It is serializable as-is, the [DSL][androidAttestationIssuer] builds it directly, and
 * [AndroidAttestationIssuer] consumes it — there is no second representation to keep in sync.
 *
 * Configuration only: no keys, no certificates, nothing that has to be generated at runtime. The
 * crypto material lives in [AndroidAttestationIssuer] and [IssuedAttestation].
 */
@Serializable
data class CreatorConfig(
    val issuer: IssuerSpec = IssuerSpec(),
    val attestations: List<AttestationSpec> = listOf(AttestationSpec()),
    val outputDirectory: String = "creator-output",
) {
    fun toJson(): String = CreatorJson.encodeToString(this)

    companion object {
        fun fromJson(json: String): CreatorConfig = CreatorJson.decodeFromString(json)
    }
}

/** How the attestation CA chain below the root is shaped. */
@Serializable
enum class Provisioning {
    /** A single factory-provisioned attestation CA directly under the root. */
    FACTORY,

    /** Remote key provisioning: `Droid CA2` and `Droid CA3` between root and attestation key. */
    RKP,
}

/** Root CA material to reuse across runs. Both PEMs must belong together. */
@Serializable
data class RootSpec(val certificatePem: String, val privateKeyPkcs8Pem: String)

/** The issuing hierarchy: which chain shape to build, from which root, valid from when. */
@Serializable
data class IssuerSpec(
    val provisioning: Provisioning = Provisioning.FACTORY,
    /** Claimed security level of the attestation CA; names the factory-provisioned CA. */
    val securityLevel: @Serializable(SecurityLevelAsName::class) SecurityLevel = SecurityLevel.TRUSTED_ENVIRONMENT,
    /** Root to reuse, or `null` to generate a fresh EC P-256 root. */
    val root: RootSpec? = null,
    val issuedAt: @Serializable(InstantAsIso8601::class) Instant = Clock.System.now(),
)

/**
 * One attestation to issue: the KeyMint statement itself, plus when the certificates start being valid.
 *
 * [keyDescription] is the parser's own type, so anything the parser can represent can be issued —
 * including `mangle`d, structurally invalid properties for negative test vectors.
 */
@Serializable
data class AttestationSpec(
    val keyDescription: @Serializable(KeyDescriptionAsSchema::class) AttestationKeyDescription = DefaultKeyDescription,
    val createdAt: @Serializable(InstantAsIso8601::class) Instant = Clock.System.now(),
)

/**
 * The statement you get when nothing is specified: an empty KeyMint 4.0 statement in a TEE.
 *
 * The single source of the creator's defaults — [AttestationSpec], the DSL and the JSON codec all
 * fall back to exactly these values.
 */
val DefaultKeyDescription: AttestationKeyDescription = AttestationKeyDescription(
    attestationVersion = KEYMINT_4_0,
    attestationSecurityLevel = SecurityLevel.TRUSTED_ENVIRONMENT,
    keyMintVersion = KEYMINT_4_0,
    keyMintSecurityLevel = SecurityLevel.TRUSTED_ENVIRONMENT,
    attestationChallenge = ByteArray(0),
    uniqueId = ByteArray(0),
    softwareEnforced = AuthorizationList(),
    hardwareEnforced = AuthorizationList(),
)

/** Attestation/KeyMint version of KeyMint 4.0, i.e. the current schema revision. */
const val KEYMINT_4_0 = 400
