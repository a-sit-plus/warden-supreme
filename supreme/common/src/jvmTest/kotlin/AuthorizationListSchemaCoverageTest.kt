import at.asitplus.attestation.android.AttestationValue
import at.asitplus.attestation.android.AuthorizationList
import at.asitplus.attestation.android.AuthorizationList.AttestationId
import at.asitplus.attestation.android.AuthorizationList.PatchLevel
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Integer
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.withClue
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kotlinx.datetime.Month
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

/**
 * Coverage of Android's attestation schema, property by property.
 *
 * Every property of [AuthorizationList] is exercised twice: once with a well-formed value, and once
 * with a value that is structurally illegal for its tag. In **both** cases the property must be
 * *present* after a decode -- as [AttestationValue.Success] or as [AttestationValue.Failure], the
 * distinction does not matter here. What must never happen is a property silently disappearing.
 *
 * Every list built here is DER-encodable, so re-encoding a decoded list must reproduce the input
 * bytes exactly. (Lists that cannot be DER-encoded make no such promise and are not tested here.)
 *
 * The table is checked against the class itself by reflection, so a property added to the schema
 * fails ["the property table covers the whole schema"] until it is listed below.
 */
val AuthorizationListSchemaCoverageTest by matrixSuite {

    "the property table covers the whole schema" {
        propertyCases.map { it.name }.toSet() shouldBe schemaProperties
        propertyCases.map { it.tag.explicitTag }.toSet().size shouldBe propertyCases.size
    }

    data("a well-formed property is present after decoding", propertyCases, nameFn = { it.name }) test { case ->
        val encoded = case.wellFormed.encodeToTlv()

        val decoded = AuthorizationList.decodeFromTlv(encoded)

        withClue("${case.name} [${case.tag.explicitTag}]") {
            case.read(decoded).shouldNotBeNull().shouldNotBeEmpty().forEach { it.isSuccess() shouldBe true }
            decoded.encodeToTlv().derEncoded shouldBe encoded.derEncoded
            decoded shouldBe case.wellFormed
        }
    }

    data("a schema-illegal property is present after decoding", propertyCases, nameFn = { it.name }) test { case ->
        val encoded = AuthorizationList
            .fromElements(listOf(AuthorizationList.Element.Unknown(case.schemaIllegalProperty())))
            .encodeToTlv()

        val decoded = AuthorizationList.decodeFromTlv(encoded)

        withClue("${case.name} [${case.tag.explicitTag}]") {
            case.read(decoded).shouldNotBeNull().shouldNotBeEmpty().forEach { it.isFailure() shouldBe true }
            decoded.encodeToTlv().derEncoded shouldBe encoded.derEncoded
        }
    }

    "every property of a maximal authorization list is present after decoding" {
        val everything = AuthorizationList.fromElements(propertyCases.flatMap { it.wellFormed.elements })
        val encoded = everything.encodeToTlv()

        val decoded = AuthorizationList.decodeFromTlv(encoded)

        decoded.elements.size shouldBe propertyCases.size
        propertyCases.forEach { case ->
            withClue("${case.name} [${case.tag.explicitTag}]") {
                case.read(decoded).shouldNotBeNull().shouldNotBeEmpty()
            }
        }
        decoded.encodeToTlv().derEncoded shouldBe encoded.derEncoded
        decoded shouldBe everything
    }

    "every property of a maximally broken authorization list is present after decoding" {
        val everything = AuthorizationList.fromElements(
            propertyCases.map { AuthorizationList.Element.Unknown(it.schemaIllegalProperty()) }
        )
        val encoded = everything.encodeToTlv()

        val decoded = AuthorizationList.decodeFromTlv(encoded)

        decoded.elements.size shouldBe propertyCases.size
        propertyCases.forEach { case ->
            withClue("${case.name} [${case.tag.explicitTag}]") {
                case.read(decoded).shouldNotBeNull().shouldNotBeEmpty().forEach { it.isFailure() shouldBe true }
            }
        }
        decoded.encodeToTlv().derEncoded shouldBe encoded.derEncoded
    }
}

/** One schema property: how to build it, how to break it, and how to read it back. */
private class PropertyCase(
    /** The property's name on [AuthorizationList]; checked against the class by reflection. */
    val name: String,
    val tag: AuthorizationList.Tagged,
    /** `true` for the `SET OF` properties, whose values the schema wraps in an ASN.1 SET. */
    val setValued: Boolean,
    /** An authorization list holding nothing but this property, with a well-formed value. */
    val wellFormed: AuthorizationList,
    /** Reads the property back, normalised to a collection so set- and single-valued cases agree. */
    val read: (AuthorizationList) -> Collection<AttestationValue<*>>?,
) {
    /**
     * The complete explicitly tagged property, carrying a BOOLEAN where the schema allows anything
     * but: no property of the schema decodes a BOOLEAN, so this always has to fail to parse.
     */
    fun schemaIllegalProperty(): Asn1Element = Asn1.ExplicitlyTagged(tag.explicitTag) {
        if (setValued) +Asn1.SetOf { +Asn1.Bool(true) } else +Asn1.Bool(true)
    }
}

private fun property(
    name: String,
    tag: AuthorizationList.Tagged,
    setValued: Boolean = false,
    wellFormed: AuthorizationList,
    read: (AuthorizationList) -> Collection<AttestationValue<*>>?,
) = PropertyCase(name, tag, setValued, wellFormed, read)

private fun single(value: AttestationValue<*>?): Collection<AttestationValue<*>>? = value?.let(::listOf)

private val timestamp = Instant.fromEpochMilliseconds(1_700_000_000_000)

private val propertyCases = listOf(
    // @formatter:off
    property("purpose", AuthorizationList.KeyPurpose, setValued = true,
        wellFormed = AuthorizationList(purpose = setOf(AuthorizationList.KeyPurpose.SIGN))) { it.purpose },
    property("algorithm", AuthorizationList.Algorithm,
        wellFormed = AuthorizationList(algorithm = AuthorizationList.Algorithm.EC)) { single(it.algorithm) },
    property("keySize", AuthorizationList.KeySize,
        wellFormed = AuthorizationList(keySize = AuthorizationList.KeySize(BitLength(256u)))) { single(it.keySize) },
    property("blockMode", AuthorizationList.BlockMode, setValued = true,
        wellFormed = AuthorizationList(blockMode = setOf(AuthorizationList.BlockMode.GCM))) { it.blockMode },
    property("digest", AuthorizationList.Digest, setValued = true,
        wellFormed = AuthorizationList(digest = setOf(AuthorizationList.Digest.SHA_2_256))) { it.digest },
    property("padding", AuthorizationList.Padding, setValued = true,
        wellFormed = AuthorizationList(padding = setOf(AuthorizationList.Padding.PKCS7))) { it.padding },
    property("callerNonce", AuthorizationList.CallerNonce,
        wellFormed = AuthorizationList(callerNonce = AuthorizationList.CallerNonce)) { single(it.callerNonce) },
    property("minMacLength", AuthorizationList.MinMacLength,
        wellFormed = AuthorizationList(minMacLength = AuthorizationList.MinMacLength(BitLength(128u)))) { single(it.minMacLength) },
    property("ecCurve", AuthorizationList.ECCurve,
        wellFormed = AuthorizationList(ecCurve = AuthorizationList.ECCurve.P_256)) { single(it.ecCurve) },
    property("rsaPublicExponent", AuthorizationList.RsaPublicExponent,
        wellFormed = AuthorizationList(rsaPublicExponent = AuthorizationList.RsaPublicExponent(Asn1Integer(65537u)))) { single(it.rsaPublicExponent) },
    property("mgfDigest", AuthorizationList.MgfDigest, setValued = true,
        wellFormed = AuthorizationList(mgfDigest = setOf(AuthorizationList.MgfDigest(Asn1Integer(4))))) { it.mgfDigest },
    property("rollbackResistance", AuthorizationList.RollbackResistance,
        wellFormed = AuthorizationList(rollbackResistance = AuthorizationList.RollbackResistance)) { single(it.rollbackResistance) },
    property("earlyBootOnly", AuthorizationList.EarlyBootOnly,
        wellFormed = AuthorizationList(earlyBootOnly = AuthorizationList.EarlyBootOnly)) { single(it.earlyBootOnly) },
    property("activeDateTime", AuthorizationList.ActiveDateTime,
        wellFormed = AuthorizationList(activeDateTime = AuthorizationList.ActiveDateTime(timestamp))) { single(it.activeDateTime) },
    property("originationExpireDateTime", AuthorizationList.OriginationExpireDateTime,
        wellFormed = AuthorizationList(originationExpireDateTime = AuthorizationList.OriginationExpireDateTime(timestamp))) { single(it.originationExpireDateTime) },
    property("usageExpireDateTime", AuthorizationList.UsageExpireDateTime,
        wellFormed = AuthorizationList(usageExpireDateTime = AuthorizationList.UsageExpireDateTime(timestamp))) { single(it.usageExpireDateTime) },
    property("usageCountLimit", AuthorizationList.UsageCountLimit,
        wellFormed = AuthorizationList(usageCountLimit = AuthorizationList.UsageCountLimit(Asn1Integer(3)))) { single(it.usageCountLimit) },
    property("userSecureId", AuthorizationList.UserSecureId,
        wellFormed = AuthorizationList(userSecureId = AuthorizationList.UserSecureId(4711))) { single(it.userSecureId) },
    property("noAuthRequired", AuthorizationList.NoAuthRequired,
        wellFormed = AuthorizationList(noAuthRequired = AuthorizationList.NoAuthRequired)) { single(it.noAuthRequired) },
    property("userAuthType", AuthorizationList.UserAuth,
        wellFormed = AuthorizationList(userAuthType = AuthorizationList.UserAuth(AuthorizationList.UserAuth.Type.FINGERPRINT))) { single(it.userAuthType) },
    property("authTimeout", AuthorizationList.AuthTimeout,
        wellFormed = AuthorizationList(authTimeout = AuthorizationList.AuthTimeout(30.seconds))) { single(it.authTimeout) },
    property("allowWhileOnBody", AuthorizationList.AllowWhileOnBody,
        wellFormed = AuthorizationList(allowWhileOnBody = AuthorizationList.AllowWhileOnBody)) { single(it.allowWhileOnBody) },
    property("trustedUserPresenceRequired", AuthorizationList.TrustedUserPresenceRequired,
        wellFormed = AuthorizationList(trustedUserPresenceRequired = AuthorizationList.TrustedUserPresenceRequired)) { single(it.trustedUserPresenceRequired) },
    property("trustedConfirmationRequired", AuthorizationList.TrustedConfirmationRequired,
        wellFormed = AuthorizationList(trustedConfirmationRequired = AuthorizationList.TrustedConfirmationRequired)) { single(it.trustedConfirmationRequired) },
    property("unlockedDeviceRequired", AuthorizationList.UnlockedDeviceRequired,
        wellFormed = AuthorizationList(unlockedDeviceRequired = AuthorizationList.UnlockedDeviceRequired)) { single(it.unlockedDeviceRequired) },
    property("allApplications", AuthorizationList.AllApplications,
        wellFormed = AuthorizationList(allApplications = AuthorizationList.AllApplications)) { single(it.allApplications) },
    property("creationDateTime", AuthorizationList.CreationDateTime,
        wellFormed = AuthorizationList(creationDateTime = AuthorizationList.CreationDateTime(timestamp))) { single(it.creationDateTime) },
    property("origin", AuthorizationList.Origin,
        wellFormed = AuthorizationList(origin = AuthorizationList.Origin.GENERATED)) { single(it.origin) },
    property("rollbackResistant", AuthorizationList.RollbackResistent,
        wellFormed = AuthorizationList(rollbackResistant = AuthorizationList.RollbackResistent)) { single(it.rollbackResistant) },
    property("rootOfTrust", AuthorizationList.RootOfTrust,
        wellFormed = AuthorizationList(rootOfTrust = AuthorizationList.RootOfTrust(
            verifiedBootKeyDigest = ByteArray(32) { 1 },
            deviceLocked = true,
            verifiedBootState = AuthorizationList.RootOfTrust.VerifiedBootState.Verified,
            verifiedBootHash = ByteArray(32) { 2 },
        ))) { single(it.rootOfTrust) },
    property("osVersion", AuthorizationList.OsVersion,
        wellFormed = AuthorizationList(osVersion = AuthorizationList.OsVersion(14u, 0u, 0u))) { single(it.osVersion) },
    property("osPatchLevel", AuthorizationList.OsPatchLevel,
        wellFormed = AuthorizationList(osPatchLevel = AuthorizationList.OsPatchLevel(2026u, Month.SEPTEMBER))) { single(it.osPatchLevel) },
    property("attestationApplicationId", AuthorizationList.AttestationApplicationId,
        wellFormed = AuthorizationList(attestationApplicationId = AuthorizationList.AttestationApplicationId(
            packageInfos = setOf(AuthorizationList.AttestationPackageInfo("at.asitplus.warden", 1u)),
            signatureDigests = setOf(ByteArray(32) { 3 }),
        ))) { single(it.attestationApplicationId) },
    property("attestationIdBrand", AttestationId.Brand,
        wellFormed = AuthorizationList(attestationIdBrand = AttestationId.Brand("google"))) { single(it.attestationIdBrand) },
    property("attestationIdDevice", AttestationId.Device,
        wellFormed = AuthorizationList(attestationIdDevice = AttestationId.Device("oriole"))) { single(it.attestationIdDevice) },
    property("attestationIdProduct", AttestationId.Product,
        wellFormed = AuthorizationList(attestationIdProduct = AttestationId.Product("oriole"))) { single(it.attestationIdProduct) },
    property("attestationIdSerial", AttestationId.Serial,
        wellFormed = AuthorizationList(attestationIdSerial = AttestationId.Serial("0123456789abcdef"))) { single(it.attestationIdSerial) },
    property("attestationIdImei", AttestationId.Imei,
        wellFormed = AuthorizationList(attestationIdImei = AttestationId.Imei("490154203237518"))) { single(it.attestationIdImei) },
    property("attestationIdMeid", AttestationId.Meid,
        wellFormed = AuthorizationList(attestationIdMeid = AttestationId.Meid("A00000319C9C1E"))) { single(it.attestationIdMeid) },
    property("attestationIdManufacturer", AttestationId.Manufacturer,
        wellFormed = AuthorizationList(attestationIdManufacturer = AttestationId.Manufacturer("Google"))) { single(it.attestationIdManufacturer) },
    property("attestationIdModel", AttestationId.Model,
        wellFormed = AuthorizationList(attestationIdModel = AttestationId.Model("Pixel 6"))) { single(it.attestationIdModel) },
    property("vendorPatchLevel", PatchLevel.Vendor,
        wellFormed = AuthorizationList(vendorPatchLevel = PatchLevel.Vendor(2026u, Month.SEPTEMBER, 5u))) { single(it.vendorPatchLevel) },
    property("bootPatchLevel", PatchLevel.Boot,
        wellFormed = AuthorizationList(bootPatchLevel = PatchLevel.Boot(2026u, Month.SEPTEMBER, null))) { single(it.bootPatchLevel) },
    property("deviceUniqueAttestation", AuthorizationList.DeviceUniqueAttestation,
        wellFormed = AuthorizationList(deviceUniqueAttestation = AuthorizationList.DeviceUniqueAttestation)) { single(it.deviceUniqueAttestation) },
    property("attestationIdSecondImei", AttestationId.SecondImei,
        wellFormed = AuthorizationList(attestationIdSecondImei = AttestationId.SecondImei("490154203237519"))) { single(it.attestationIdSecondImei) },
    property("moduleHash", AuthorizationList.ModuleHash,
        wellFormed = AuthorizationList(moduleHash = AuthorizationList.ModuleHash(ByteArray(32) { 4 }))) { single(it.moduleHash) },
    // @formatter:on
)

/**
 * The schema properties as the class itself declares them: every parameterless getter returning an
 * [AttestationValue] (single-valued) or a [Set] of them (`SET OF`).
 */
private val schemaProperties: Set<String> = AuthorizationList::class.java.methods
    .filter { it.parameterCount == 0 && it.name.startsWith("get") }
    .filter { AttestationValue::class.java.isAssignableFrom(it.returnType) || Set::class.java.isAssignableFrom(it.returnType) }
    .map { it.name.removePrefix("get").replaceFirstChar(Char::lowercaseChar) }
    .toSet()
