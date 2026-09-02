package at.asitplus.attestation.creator

import at.asitplus.attestation.android.AttestationKeyDescription
import at.asitplus.attestation.android.AttestationKeyDescription.SecurityLevel
import at.asitplus.attestation.android.AuthorizationList
import kotlinx.serialization.Serializable
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
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

/**
 * How the chain between root and attestation key is shaped, i.e. what
 * `KeyAttestationCertPath.provisioningMethod()` will make of it.
 *
 * The shape is what a verifier reads the security level off, so it is not cosmetic: the subject names
 * below follow Android's real chains.
 */
@Serializable
enum class Provisioning {
    /** No CA between root and attestation key: a software-backed chain, provisioning method unknown. */
    SOFTWARE,

    /** One factory-provisioned CA (`serialNumber=<hex>, title=TEE|StrongBox`) under the root. */
    FACTORY,

    /** Remote key provisioning: `Droid CA2` and `Droid CA3`, both `O=Google LLC`, under the root. */
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
    /** How long every issued certificate stays valid, counted from when it was issued. */
    val validity: @Serializable(DurationAsIso8601::class) Duration = 365.days,
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
    /**
     * Issues the attested leaf as a CA that may sign certificates. Real attested keys never can; this
     * exists to build chain-extension attack vectors, where a leaf signs a certificate of its own.
     */
    val leafCanSignCertificates: Boolean = false,
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
