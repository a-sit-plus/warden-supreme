package at.asitplus.attestation.creator

import at.asitplus.attestation.android.AttestationKeyDescription
import at.asitplus.attestation.android.AttestationKeyDescription.SecurityLevel
import at.asitplus.attestation.android.AuthorizationList
import kotlin.time.Duration
import kotlin.time.Instant

/**
 * ### DSL
 *
 * The builders below produce nothing but [CreatorConfig] parts and hand them straight to
 * [AndroidAttestationIssuer]. They add defaults and ergonomics — never fields, meaning, or a model of
 * their own. Authorization lists are not built here at all: the parser's own
 * [AuthorizationList] constructor is already a complete, type-safe, named-argument builder for the
 * whole schema, and `AuthorizationList.mangle(…)` covers the negative-test cases.
 */

@DslMarker
annotation class CreatorDsl

/** Builds an issuer, generating a fresh EC P-256 root and a factory-provisioned TEE CA by default. */
fun androidAttestationIssuer(block: IssuerSpecBuilder.() -> Unit = {}): AndroidAttestationIssuer =
    AndroidAttestationIssuer.from(issuerSpec(block))

fun issuerSpec(block: IssuerSpecBuilder.() -> Unit = {}): IssuerSpec = IssuerSpecBuilder().apply(block).build()

@CreatorDsl
class IssuerSpecBuilder internal constructor(defaults: IssuerSpec = IssuerSpec()) {
    var provisioning: Provisioning = defaults.provisioning
    var securityLevel: SecurityLevel = defaults.securityLevel

    /** Root material to reuse; `null` (the default) generates a fresh EC P-256 root. */
    var root: RootSpec? = defaults.root
    var issuedAt: Instant = defaults.issuedAt

    /** How long every issued certificate stays valid. */
    var validity: Duration = defaults.validity

    /** A software-backed chain: the root signs attestation keys itself, with no CA in between. */
    fun softwareBacked(level: SecurityLevel = SecurityLevel.SOFTWARE) {
        provisioning = Provisioning.SOFTWARE
        securityLevel = level
    }

    fun factoryProvisioned(level: SecurityLevel = SecurityLevel.TRUSTED_ENVIRONMENT) {
        provisioning = Provisioning.FACTORY
        securityLevel = level
    }

    fun rkp(level: SecurityLevel = SecurityLevel.TRUSTED_ENVIRONMENT) {
        provisioning = Provisioning.RKP
        securityLevel = level
    }

    fun importedRoot(certificatePem: String, privateKeyPkcs8Pem: String) {
        root = RootSpec(certificatePem, privateKeyPkcs8Pem)
    }

    internal fun build() = IssuerSpec(provisioning, securityLevel, root, issuedAt, validity)
}

fun attestationSpec(block: AttestationSpecBuilder.() -> Unit = {}): AttestationSpec =
    AttestationSpecBuilder().apply(block).build()

/** Builder for one KeyMint statement, i.e. one [AttestationKeyDescription] plus its issuance date. */
@CreatorDsl
class AttestationSpecBuilder internal constructor(defaults: AttestationSpec = AttestationSpec()) {
    private val default = defaults.keyDescription

    var createdAt: Instant = defaults.createdAt
    var attestationVersion: Int = default.attestationVersion
    var keyMintVersion: Int = default.keyMintVersion

    /** Both security levels at once, the way real statements have them. */
    var securityLevel: SecurityLevel = default.keyMintSecurityLevel

    /** Overrides [securityLevel] for the attestation itself. */
    var attestationSecurityLevel: SecurityLevel? = null

    /** Overrides [securityLevel] for the attested key. */
    var keyMintSecurityLevel: SecurityLevel? = null

    /** The attestation challenge. */
    var nonce: ByteArray = default.attestationChallenge
    var uniqueId: ByteArray = default.uniqueId
    var softwareEnforced: AuthorizationList = default.softwareEnforced
    var hardwareEnforced: AuthorizationList = default.hardwareEnforced

    /** Issues the attested leaf as a CA, for chain-extension attack vectors. Never true on a device. */
    var leafCanSignCertificates: Boolean = defaults.leafCanSignCertificates

    internal fun build() = AttestationSpec(
        keyDescription = AttestationKeyDescription(
            attestationVersion = attestationVersion,
            attestationSecurityLevel = attestationSecurityLevel ?: securityLevel,
            keyMintVersion = keyMintVersion,
            keyMintSecurityLevel = keyMintSecurityLevel ?: securityLevel,
            attestationChallenge = nonce,
            uniqueId = uniqueId,
            softwareEnforced = softwareEnforced,
            hardwareEnforced = hardwareEnforced,
        ),
        createdAt = createdAt,
        leafCanSignCertificates = leafCanSignCertificates,
    )
}
