@file:OptIn(ExperimentalStdlibApi::class)

package at.asitplus.attestation.generator

import at.asitplus.attestation.android.AttestationKeyDescription.SecurityLevel
import at.asitplus.attestation.android.AuthorizationList
import at.asitplus.attestation.android.androidAttestationExtension
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.property.Arb
import io.kotest.property.Exhaustive
import io.kotest.property.RandomSource
import io.kotest.property.arbitrary.bind
import io.kotest.property.arbitrary.boolean
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.enum
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.long
import io.kotest.property.arbitrary.string
import io.kotest.property.exhaustive.boolean
import io.kotest.property.exhaustive.enum
import io.kotest.property.exhaustive.times
import kotlinx.datetime.Month
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.util.Date
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

val GeneratorDslTest by matrixSuite {
    "DSL issues an Android Keystore shaped attestation" {
        val nonce = byteArrayOf(1, 2, 3, 4)
        val issued = androidAttestationIssuer { factoryProvisioned(SecurityLevel.TRUSTED_ENVIRONMENT) }.issue {
            this.nonce = nonce
            hardwareEnforced = AuthorizationList(
                purpose = setOf(AuthorizationList.KeyPurpose.SIGN),
                algorithm = AuthorizationList.Algorithm.EC,
                ecCurve = AuthorizationList.ECCurve.P_256,
                noAuthRequired = AuthorizationList.NoAuthRequired,
                origin = AuthorizationList.Origin.GENERATED,
            )
        }

        issued.certificateChain.size shouldBe 4 // leaf, attestation, factory CA, root
        val description = requireNotNull(issued.leafCertificate.androidAttestationExtension)
        description.attestationChallenge.contentEquals(nonce) shouldBe true
        description.keyMintSecurityLevel shouldBe SecurityLevel.TRUSTED_ENVIRONMENT
        description.hardwareEnforced.algorithm?.getOrThrow() shouldBe AuthorizationList.Algorithm.EC
        description.hardwareEnforced.purpose?.map { it.getOrThrow() }?.toSet() shouldBe
                setOf(AuthorizationList.KeyPurpose.SIGN)
    }

    "RKP DSL creates the expected multi-CA shape" {
        val issued = androidAttestationIssuer { rkp(SecurityLevel.STRONGBOX) }
            .issue { securityLevel = SecurityLevel.STRONGBOX }

        issued.certificateChain.size shouldBe 5 // leaf, attestation, Droid CA3, Droid CA2, root
        requireNotNull(issued.leafCertificate.androidAttestationExtension)
            .keyMintSecurityLevel shouldBe SecurityLevel.STRONGBOX
    }

    "diverse schema properties survive issuance" {
        val timestamp = Clock.System.now()
        val rootOfTrust = AuthorizationList.RootOfTrust(
            verifiedBootKeyDigest = byteArrayOf(9, 8, 7),
            deviceLocked = true,
            verifiedBootState = AuthorizationList.RootOfTrust.VerifiedBootState.Verified,
            verifiedBootHash = byteArrayOf(6, 5, 4),
        )
        val hardware = AuthorizationList(
            purpose = setOf(AuthorizationList.KeyPurpose.SIGN, AuthorizationList.KeyPurpose.VERIFY),
            blockMode = setOf(AuthorizationList.BlockMode.GCM),
            digest = setOf(AuthorizationList.Digest.SHA_2_256),
            padding = setOf(AuthorizationList.Padding.PKCS7),
            callerNonce = AuthorizationList.CallerNonce,
            earlyBootOnly = AuthorizationList.EarlyBootOnly,
            activeDateTime = AuthorizationList.ActiveDateTime(timestamp),
            userSecureId = AuthorizationList.UserSecureId(1234),
            userAuthType = AuthorizationList.UserAuth(AuthorizationList.UserAuth.Type.FINGERPRINT),
            authTimeout = AuthorizationList.AuthTimeout(30.seconds),
            trustedUserPresenceRequired = AuthorizationList.TrustedUserPresenceRequired,
            unlockedDeviceRequired = AuthorizationList.UnlockedDeviceRequired,
            rootOfTrust = rootOfTrust,
            osVersion = AuthorizationList.OsVersion(14u, 1u, 0u),
            osPatchLevel = AuthorizationList.OsPatchLevel(2026u, Month.SEPTEMBER),
        )

        val issued = androidAttestationIssuer().issue { hardwareEnforced = hardware }

        val parsed = requireNotNull(issued.leafCertificate.androidAttestationExtension).hardwareEnforced
        parsed shouldBe hardware
        parsed.blockMode?.map { it.getOrThrow() }?.toSet() shouldBe setOf(AuthorizationList.BlockMode.GCM)
        parsed.userSecureId?.getOrThrow() shouldBe AuthorizationList.UserSecureId(1234)
        parsed.authTimeout?.getOrThrow()?.duration shouldBe 30.seconds
        parsed.rootOfTrust?.getOrThrow() shouldBe rootOfTrust
        parsed.osVersion?.getOrThrow() shouldBe AuthorizationList.OsVersion(14u, 1u, 0u)
        parsed.osPatchLevel?.getOrThrow() shouldBe AuthorizationList.OsPatchLevel(2026u, Month.SEPTEMBER)
    }

    "mangled properties are issued verbatim and survive the config round-trip" {
        // [3] EXPLICIT INTEGER 128 where a proper keySize would be: valid ASN.1, wrong by intent.
        val mangledDer = "a30402020080"
        val spec = attestationSpec {
            hardwareEnforced = AuthorizationList(algorithm = AuthorizationList.Algorithm.EC)
                .mangle(AuthorizationList.KeySize, mangledDer)
        }

        val issued = androidAttestationIssuer().issue(spec)
        requireNotNull(issued.leafCertificate.androidAttestationExtension)
            .hardwareEnforced.encodeToTlv().derEncoded shouldBe
                spec.keyDescription.hardwareEnforced.encodeToTlv().derEncoded

        val json = GeneratorConfig(attestations = listOf(spec)).toJson()
        json.contains(mangledDer) shouldBe true
        GeneratorConfig.fromJson(json).attestations.single().keyDescription.encodeToTlv().derEncoded shouldBe
                spec.keyDescription.encodeToTlv().derEncoded
    }

    // ---- data-driven: every issuer shape, against generated statements ------------------------

    val shapes = Exhaustive.enum<SecurityLevel>() * Exhaustive.boolean()
    val issuers = shapes.values.associateWith { (level, rkp) ->
        androidAttestationIssuer { if (rkp) rkp(level) else factoryProvisioned(level) }
    }
    val sharedRoot = requireNotNull(issuers.values.first().spec.root)

    fun cases(count: Int, seed: Long) = statementArb
        .samples(RandomSource.seeded(seed))
        .take(count)
        .map { it.value }
        .withIndex()
        .flatMap { (index, statement) -> shapes.values.asSequence().map { Case(index, it.first, it.second, statement) } }
        .toList()

    // One property at a time: a failure here names the offending tag instead of a 40-property diff.
    val singleProperty = statementArb.samples(RandomSource.seeded(0x50524F5054594CL)).first().value.hardwareEnforced

    data(
        "every schema property survives the config round-trip on its own",
        (0 until AuthorizationListRecipe.PROPERTY_COUNT).toList(),
        nameFn = { "property-bit-$it" },
    ) test { bit ->
        val spec = attestationSpec { hardwareEnforced = singleProperty.only(bit).build() }
        val decoded = GeneratorConfig.fromJson(GeneratorConfig(attestations = listOf(spec)).toJson())

        decoded.attestations.single().keyDescription shouldBe spec.keyDescription
    }

    val roundTripCases = cases(count = 250, seed = 0x415454455354L)

    data(
        "generator configuration JSON round-trip",
        roundTripCases,
        nameFn = { it.name },
    ) test { case ->
        val config = GeneratorConfig(
            issuer = issuerSpec {
                root = sharedRoot
                if (case.rkp) rkp(case.level) else factoryProvisioned(case.level)
                issuedAt = case.statement.issuedAt
            },
            attestations = listOf(case.statement.spec(case.level, case.statement.issuedAt)),
            outputDirectory = case.statement.outputDirectory,
        )

        val json = config.toJson()
        val decoded = GeneratorConfig.fromJson(json)

        decoded shouldBe config
        // ... and byte-for-byte, which is the part the generator actually promises to reproduce.
        decoded.attestations.map { it.keyDescription.encodeToTlv().derEncoded.toHexString() } shouldBe
                config.attestations.map { it.keyDescription.encodeToTlv().derEncoded.toHexString() }
        decoded.toJson() shouldBe json
    }

    val issuanceCases = cases(count = 4, seed = 0x4B45594D494E54L)

    data(
        "generated statements are issued into strictly valid chains",
        issuanceCases,
        nameFn = { it.name },
    ) test { case ->
        val issuer = issuers.getValue(case.level to case.rkp)
        // Certificates start being valid somewhere inside the issuer's own validity window.
        val createdAt = issuer.spec.issuedAt + case.statement.offsetDays.days
        val spec = case.statement.spec(case.level, createdAt)

        val issued = issuer.issue(spec)

        issued.certificateChain.size shouldBe if (case.rkp) 5 else 4
        requireNotNull(issued.leafCertificate.androidAttestationExtension)
            .encodeToTlv().derEncoded shouldBe spec.keyDescription.encodeToTlv().derEncoded

        // A CA per position, each stating how many CA certificates may follow it; leaf is an end entity.
        issued.leafCertificate.basicConstraints shouldBe null
        issued.certificateChain.drop(1).dropLast(1).forEachIndexed { index, ca ->
            ca.basicConstraints shouldNotBe null
            ca.pathLength shouldBe index
        }
        issued.rootCertificate.pathLength shouldBe null // unconstrained, as Google's root is

        issued.validateStrictPkix(at = createdAt + 1.days)
    }
}

// ---- generated input ---------------------------------------------------------------------------

private data class Case(
    val index: Int,
    val level: SecurityLevel,
    val rkp: Boolean,
    val statement: GeneratedStatement,
) {
    val name: String = "${if (rkp) "RKP" else "factory"}-${level.name}-generated-$index"
}

/**
 * One generated KeyMint statement: the scalar header fields, plus two authorization lists assembled
 * from [AuthorizationListRecipe.mask] — a random subset of the schema, not the same five properties
 * over and over.
 */
private data class GeneratedStatement(
    val attestationVersion: Int,
    val keyMintVersion: Int,
    val nonce: ByteArray,
    val uniqueId: ByteArray,
    val epochSeconds: Int,
    val offsetDays: Int,
    val outputDirectory: String,
    val softwareEnforced: AuthorizationListRecipe,
    val hardwareEnforced: AuthorizationListRecipe,
) {
    val issuedAt: Instant get() = Instant.fromEpochSeconds(epochSeconds.toLong())

    fun spec(level: SecurityLevel, createdAt: Instant) = attestationSpec {
        this.createdAt = createdAt
        securityLevel = level
        attestationVersion = this@GeneratedStatement.attestationVersion
        keyMintVersion = this@GeneratedStatement.keyMintVersion
        nonce = this@GeneratedStatement.nonce
        uniqueId = this@GeneratedStatement.uniqueId
        softwareEnforced = this@GeneratedStatement.softwareEnforced.build()
        hardwareEnforced = this@GeneratedStatement.hardwareEnforced.build()
    }
}

private data class SchemaEnums(
    val purpose: AuthorizationList.KeyPurpose,
    val algorithm: AuthorizationList.Algorithm,
    val blockMode: AuthorizationList.BlockMode,
    val digest: AuthorizationList.Digest,
    val padding: AuthorizationList.Padding,
    val ecCurve: AuthorizationList.ECCurve,
    val origin: AuthorizationList.Origin,
    val userAuth: AuthorizationList.UserAuth.Type,
    val bootState: AuthorizationList.RootOfTrust.VerifiedBootState,
    val month: Month,
)

private data class SchemaNumbers(
    val keySizeBits: Int,
    val macLengthBits: Int,
    val userSecureId: Long,
    val authTimeoutSeconds: Int,
    val usageCount: Int,
    val osMajor: Int,
    val osMinor: Int,
    val osSub: Int,
    val patchYear: Int,
    val patchDay: Int,
    val packageVersion: Int,
)

private data class SchemaBlobs(
    val bootKeyDigest: ByteArray,
    val bootHash: ByteArray,
    val moduleHash: ByteArray,
    val signatureDigest: ByteArray,
    val brand: String,
    val packageName: String,
    val deviceLocked: Boolean,
)

private data class AuthorizationListRecipe(
    val mask: Long,
    val enums: SchemaEnums,
    val numbers: SchemaNumbers,
    val blobs: SchemaBlobs,
) {
    private fun <T> pick(bit: Int, value: () -> T): T? = if (mask and (1L shl bit) != 0L) value() else null

    /** The same recipe with [bit] as its only property, for isolating one property per test. */
    fun only(bit: Int) = copy(mask = 1L shl bit)

    companion object {
        /** Number of schema properties [build] can emit; bit *n* selects the *n*th. */
        const val PROPERTY_COUNT = 46
    }

    fun build(): AuthorizationList = AuthorizationList(
        purpose = pick(0) { setOf(enums.purpose) },
        algorithm = pick(1) { enums.algorithm },
        keySize = pick(2) { AuthorizationList.KeySize(BitLength(numbers.keySizeBits.toUInt())) },
        blockMode = pick(3) { setOf(enums.blockMode) },
        digest = pick(4) { setOf(enums.digest) },
        padding = pick(5) { setOf(enums.padding) },
        callerNonce = pick(6) { AuthorizationList.CallerNonce },
        minMacLength = pick(7) { AuthorizationList.MinMacLength(BitLength(numbers.macLengthBits.toUInt())) },
        ecCurve = pick(8) { enums.ecCurve },
        mgfDigest = pick(9) { setOf(AuthorizationList.MgfDigest(asn1Integer(numbers.usageCount))) },
        rollbackResistance = pick(10) { AuthorizationList.RollbackResistance },
        earlyBootOnly = pick(11) { AuthorizationList.EarlyBootOnly },
        activeDateTime = pick(12) { AuthorizationList.ActiveDateTime(instant(numbers.usageCount)) },
        originationExpireDateTime = pick(13) {
            AuthorizationList.OriginationExpireDateTime(instant(numbers.usageCount))
        },
        usageExpireDateTime = pick(14) { AuthorizationList.UsageExpireDateTime(instant(numbers.patchDay)) },
        usageCountLimit = pick(15) { AuthorizationList.UsageCountLimit(asn1Integer(numbers.usageCount)) },
        userSecureId = pick(16) { AuthorizationList.UserSecureId(numbers.userSecureId) },
        noAuthRequired = pick(17) { AuthorizationList.NoAuthRequired },
        userAuthType = pick(18) { AuthorizationList.UserAuth(enums.userAuth) },
        authTimeout = pick(19) { AuthorizationList.AuthTimeout(numbers.authTimeoutSeconds.seconds) },
        allowWhileOnBody = pick(20) { AuthorizationList.AllowWhileOnBody },
        trustedUserPresenceRequired = pick(21) { AuthorizationList.TrustedUserPresenceRequired },
        trustedConfirmationRequired = pick(22) { AuthorizationList.TrustedConfirmationRequired },
        unlockedDeviceRequired = pick(23) { AuthorizationList.UnlockedDeviceRequired },
        allApplications = pick(24) { AuthorizationList.AllApplications },
        creationDateTime = pick(25) { AuthorizationList.CreationDateTime(instant(numbers.usageCount)) },
        origin = pick(26) { enums.origin },
        rollbackResistant = pick(27) { AuthorizationList.RollbackResistent },
        rootOfTrust = pick(28) {
            AuthorizationList.RootOfTrust(
                verifiedBootKeyDigest = blobs.bootKeyDigest,
                deviceLocked = blobs.deviceLocked,
                verifiedBootState = enums.bootState,
                verifiedBootHash = blobs.bootHash,
            )
        },
        osVersion = pick(29) {
            AuthorizationList.OsVersion(
                numbers.osMajor.toUByte(), numbers.osMinor.toUByte(), numbers.osSub.toUByte()
            )
        },
        osPatchLevel = pick(30) { AuthorizationList.OsPatchLevel(numbers.patchYear.toUShort(), enums.month) },
        attestationApplicationId = pick(31) {
            AuthorizationList.AttestationApplicationId(
                packageInfos = setOf(
                    AuthorizationList.AttestationPackageInfo(blobs.packageName, numbers.packageVersion.toUInt())
                ),
                signatureDigests = setOf(blobs.signatureDigest),
            )
        },
        attestationIdBrand = pick(32) { AuthorizationList.AttestationId.Brand(blobs.brand) },
        attestationIdDevice = pick(33) { AuthorizationList.AttestationId.Device(blobs.packageName) },
        attestationIdSerial = pick(34) { AuthorizationList.AttestationId.Serial(blobs.brand) },
        attestationIdImei = pick(35) { AuthorizationList.AttestationId.Imei(blobs.brand) },
        attestationIdManufacturer = pick(36) { AuthorizationList.AttestationId.Manufacturer(blobs.brand) },
        attestationIdModel = pick(37) { AuthorizationList.AttestationId.Model(blobs.packageName) },
        vendorPatchLevel = pick(38) {
            AuthorizationList.PatchLevel.Vendor(
                numbers.patchYear.toUShort(), enums.month, numbers.patchDay.toUShort()
            )
        },
        bootPatchLevel = pick(39) {
            AuthorizationList.PatchLevel.Boot(numbers.patchYear.toUShort(), enums.month, null)
        },
        deviceUniqueAttestation = pick(40) { AuthorizationList.DeviceUniqueAttestation },
        attestationIdSecondImei = pick(41) { AuthorizationList.AttestationId.SecondImei(blobs.brand) },
        moduleHash = pick(42) { AuthorizationList.ModuleHash(blobs.moduleHash) },
        attestationIdProduct = pick(44) { AuthorizationList.AttestationId.Product(blobs.packageName) },
        attestationIdMeid = pick(45) { AuthorizationList.AttestationId.Meid(blobs.brand) },
        // A property outside the schema entirely: devices emit these, and they must round-trip untouched.
        trailingProperties = pick(43) {
            listOf<Asn1Element>(Asn1.ExplicitlyTagged(9998uL) { +Asn1.Int(numbers.usageCount) })
        } ?: emptyList(),
    )
}

private fun asn1Integer(value: Int) = at.asitplus.signum.indispensable.asn1.Asn1Integer(value)
private fun instant(seconds: Int) = Instant.fromEpochSeconds(seconds.toLong())

private val schemaEnumsArb = Arb.bind(
    Arb.enum<AuthorizationList.KeyPurpose>(),
    Arb.enum<AuthorizationList.Algorithm>(),
    Arb.enum<AuthorizationList.BlockMode>(),
    Arb.enum<AuthorizationList.Digest>(),
    Arb.enum<AuthorizationList.Padding>(),
    Arb.enum<AuthorizationList.ECCurve>(),
    Arb.enum<AuthorizationList.Origin>(),
    Arb.enum<AuthorizationList.UserAuth.Type>(),
    Arb.enum<AuthorizationList.RootOfTrust.VerifiedBootState>(),
    Arb.enum<Month>(),
    ::SchemaEnums,
)

private val schemaNumbersArb = Arb.bind(
    Arb.int(1..8192),
    Arb.int(1..512),
    Arb.long(0L..Long.MAX_VALUE),
    Arb.int(0..86_400),
    Arb.int(0..Int.MAX_VALUE),
    Arb.int(0..25),
    Arb.int(0..99),
    Arb.int(0..99),
    Arb.int(2000..2100),
    Arb.int(1..28),
    Arb.int(0..Int.MAX_VALUE),
    ::SchemaNumbers,
)

private val schemaBlobsArb = Arb.bind(
    Arb.byteArray(Arb.int(1..32), Arb.byte()),
    Arb.byteArray(Arb.int(1..32), Arb.byte()),
    Arb.byteArray(Arb.int(32..32), Arb.byte()),
    Arb.byteArray(Arb.int(1..32), Arb.byte()),
    Arb.string(1..24),
    Arb.string(1..24),
    Arb.boolean(),
    ::SchemaBlobs,
)

private val recipeArb = Arb.bind(Arb.long(), schemaEnumsArb, schemaNumbersArb, schemaBlobsArb, ::AuthorizationListRecipe)

private val statementArb = Arb.bind(
    // STRONGBOX is only defined from attestation version 3 onwards, see AttestationKeyDescription.versionCheck
    Arb.int(3..10_000),
    Arb.int(1..10_000),
    Arb.byteArray(Arb.int(0..32), Arb.byte()),
    Arb.byteArray(Arb.int(0..32), Arb.byte()),
    Arb.int(0..Int.MAX_VALUE),
    Arb.int(0..300),
    Arb.string(1..16),
    recipeArb,
    recipeArb,
    ::GeneratedStatement,
)

// ---- assertions on real X.509 ------------------------------------------------------------------

private val at.asitplus.signum.indispensable.pki.X509Certificate.basicConstraints
    get() = tbsCertificate.extensions?.firstOrNull { it.oid.toString() == "2.5.29.19" }

private val at.asitplus.signum.indispensable.pki.X509Certificate.pathLength: Int?
    get() = asJava.basicConstraints.let { if (it == Int.MAX_VALUE || it < 0) null else it }

private val at.asitplus.signum.indispensable.pki.X509Certificate.asJava: java.security.cert.X509Certificate
    get() = CertificateFactory.getInstance("X.509")
        .generateCertificate(encodeToTlv().derEncoded.inputStream()) as java.security.cert.X509Certificate

/** Full RFC 5280 path validation by the JVM: signatures, basic constraints, path length, key usage. */
private fun IssuedAttestation.validateStrictPkix(at: Instant) {
    val anchor = TrustAnchor(rootCertificate.asJava, null)
    val path = CertificateFactory.getInstance("X.509")
        .generateCertPath(certificateChain.dropLast(1).map { it.asJava })
    val parameters = PKIXParameters(setOf(anchor)).apply {
        isRevocationEnabled = false
        date = Date(at.toEpochMilliseconds())
    }
    CertPathValidator.getInstance("PKIX").validate(path, parameters)
}
