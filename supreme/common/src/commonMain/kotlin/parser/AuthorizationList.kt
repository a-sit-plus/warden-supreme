@file:OptIn(ExperimentalTime::class)

package at.asitplus.attestation.android

import at.asitplus.attestation.android.AuthorizationList.UserAuth.Type
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.*
import at.asitplus.signum.indispensable.misc.BitLength
import kotlinx.datetime.Month
import kotlinx.datetime.number
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * #### Intro
 * Authorization List ASN.1 sequence as defined by Android’s attestation schema:
 * https://source.android.com/docs/security/features/keystore/attestation#schema
 *
 * This is the meat of the [AttestationKeyDescription] certificate extension and is also used for secure key import.
 *
 * #### Sources / Constants
 * The numeric values and semantics used here are aligned with:
 * - KeyMint AIDL definitions (enum values, etc.):
 *   https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/
 * - Keymaster header constants (historical reference):
 *   https://android.googlesource.com/platform/hardware/libhardware/+/refs/heads/main/include_all/hardware/keymaster_defs.h
 * - Note: some online sources disagree with the schema for certain values (example discussion):
 *   https://android.googlesource.com/platform/frameworks/base/+blame/45ff13e/core/java/android/security/keymaster/KeymasterDefs.java
 *
 * Every value is nullable because two authorization lists are present in an attestation extension:
 * once for software-enforced values, and once for hardware-enforced value.
 * The actual values are scattered across both instances.
 *
 * #### On Parsing
 * **Parsing is lenient:** If a value fails to parse, it is set to null. In reality,
 * you won't care whether a value is structurally illegal or absent:
 * * If you want to enforce it, it must be present and structurally valid, fulfilling your constraints
 * * If you don't care for it, you don't care whether it is present, invalid, or absent altogether
 * In case you still want to explore the raw value, check the raw ASN.1 Sequence from the certificate extension and fetch
 * the raw value according to the explicit tag denoting said value.
 *
 * #### Structural Properties and Design Decisions
 * **Structurally, this data structure follows the ASN.1 schema _exactly_**, meaning that it is a structural 1:1 mapping
 * if the underlying ASN.1 structure.
 * This as both advantages and disadvantages. The main disadvantage is that it is a bit cumbersome to use. The benefits
 * far outweigh the shortcomings of this approach, though:
 * * Just check the schema, and you know what's what. That means that there are no booleans, but an object indicating
 * `true` or `false` is either present or absent.
 * * Re-Encoding produces the exact same ASN.1 structure that was parsed, byte-for-byte!
 * * Creating Attestation statements for testing, fun, profit, or malicious intentions is a peak no-brainer;
 * just follow the schema and set values!
 *
 * #### Encoding and Ordering
 * [AuthorizationList] preserves the original order of the ASN.1 sequence during decoding by storing all decoded entries
 * (including unknown tags) in [elements].
 *
 * For ASN.1 SET fields (e.g. [purpose], [blockMode], [digest], [padding], [mgfDigest], and also
 * [AttestationApplicationId.packageInfos]/[AttestationApplicationId.signatureDigests]):
 * - When decoding, an internal order-preserving [Set] implementation is used so iteration keeps the original element
 *   order from the input (even if the input violates DER sorting).
 * - The public API still exposes these values as regular Kotlin [Set]s.
 * - When encoding, if such an order-preserving set is present, the produced ASN.1 SET preserves that iteration order
 *   (which may be non-DER-compliant). Otherwise, normal SET encoding is used.
 *
 */
data class AuthorizationList private constructor(
    val elements: List<Element>
) : Asn1Encodable<Asn1Sequence>, PrettyPrintable {
    /**
     * A single entry inside the [AuthorizationList] ASN.1 sequence.
     *
     * The list of [elements] is the source of truth for ordering and for round-trip encoding.
     */
    sealed interface Element {
        data class Single(val value: Tagged.WithTag<*>) : Element
        data class SetOf(val value: Set<Tagged.WithTag<*>>) : Element
        data class Unknown(val value: Asn1Element) : Element
    }

    /**
     * Internal [Set] implementation that preserves insertion/iteration order.
     *
     * This is used when decoding ASN.1 SET values to keep broken-but-useful source order without exposing any custom
     * collection type publicly.
     */
    private class OrderPreservingSet<E>(
        private val delegate: LinkedHashSet<E>
    ) : Set<E> by delegate {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Set<*>) return false
            if (other.size != this.size) return false
            return catchingUnwrapped {
                this.containsAll(other)
            }.getOrElse { false }
        }

        override fun hashCode(): Int = delegate.hashCode()
    }

    /**
     * Convenience constructor that builds an [AuthorizationList] from the fields defined by Android’s attestation schema.
     *
     * The resulting [elements] list is emitted in schema order (independent of the argument order). Any
     * [trailingProperties] are wrapped as [Element.Unknown] entries and appended *at the end* of the sequence.
     *
     * If you need full control over ordering or want to interleave properties outside the attestation schema, construct
     * an [AuthorizationList] from a manually assembled [elements] list via the primary constructor.
     *
     * @param trailingProperties Additional ASN.1 elements to append after all schema-defined fields.
     */
    constructor(
        // @formatter:off
        purpose                     : Set<KeyPurpose>?             = null,
        algorithm                   : Algorithm?                   = null,
        keySize                     : KeySize?                     = null,
        blockMode                   : Set<BlockMode>?              = null,
        digest                      : Set<Digest>?                 = null,
        padding                     : Set<Padding>?                = null,
        callerNonce                 : CallerNonce?                 = null,
        minMacLength                : MinMacLength?                = null,
        ecCurve                     : ECCurve?                     = null,
        rsaPublicExponent           : RsaPublicExponent?           = null,
        mgfDigest                   : Set<MgfDigest>?              = null,
        rollbackResistance          : RollbackResistance?          = null,
        earlyBootOnly               : EarlyBootOnly?               = null,
        activeDateTime              : ActiveDateTime?              = null,
        originationExpireDateTime   : OriginationExpireDateTime?   = null,
        usageExpireDateTime         : UsageExpireDateTime?         = null,
        usageCountLimit             : UsageCountLimit?             = null,
        userSecureId                : UserSecureId?                = null,
        noAuthRequired              : NoAuthRequired?              = null,
        userAuthType                : UserAuth?                    = null,
        authTimeout                 : AuthTimeout?                 = null,
        allowWhileOnBody            : AllowWhileOnBody?            = null,
        trustedUserPresenceRequired : TrustedUserPresenceRequired? = null,
        trustedConfirmationRequired : TrustedConfirmationRequired? = null,
        unlockedDeviceRequired      : UnlockedDeviceRequired?      = null,
        allApplications             : AllApplications?             = null,
        creationDateTime            : CreationDateTime?            = null,
        origin                      : Origin?                      = null,
        rollbackResistant           : RollbackResistent?           = null,
        rootOfTrust                 : RootOfTrust?                 = null,
        osVersion                   : OsVersion?                   = null,
        osPatchLevel                : OsPatchLevel?                = null,
        attestationApplicationId    : AttestationApplicationId?    = null,
        attestationIdBrand          : AttestationId.Brand?         = null,
        attestationIdDevice         : AttestationId.Device?        = null,
        attestationIdProduct        : AttestationId.Product?       = null,
        attestationIdSerial         : AttestationId.Serial?        = null,
        attestationIdImei           : AttestationId.Imei?          = null,
        attestationIdMeid           : AttestationId.Meid?          = null,
        attestationIdManufacturer   : AttestationId.Manufacturer?  = null,
        attestationIdModel          : AttestationId.Model?         = null,
        vendorPatchLevel            : PatchLevel.Vendor?           = null,
        bootPatchLevel              : PatchLevel.Boot?             = null,
        deviceUniqueAttestation     : DeviceUniqueAttestation?     = null,
        attestationIdSecondImei     : AttestationId.SecondImei?    = null,
        moduleHash                  : ModuleHash?                  = null,
        trailingProperties          : List<Asn1Element>            = emptyList(),
        // @formatter:on
    ) : this(
        buildList {
            // @formatter:off
            purpose                      ?.let { add(Element. SetOf  ( it.map { AttestationValue.Success(it, KeyPurpose)        }.toSet()   )) }
            algorithm                    ?.let { add(Element. Single ( value =  AttestationValue.Success(it, Algorithm)                     )) }
            keySize                      ?.let { add(Element. Single ( value =  AttestationValue.Success(it, KeySize)                       )) }
            blockMode                    ?.let { add(Element. SetOf  ( it.map { AttestationValue.Success(it, BlockMode)          }.toSet()   )) }
            digest                       ?.let { add(Element. SetOf  ( it.map { AttestationValue.Success(it, Digest)            }.toSet()   )) }
            padding                      ?.let { add(Element. SetOf  ( it.map { AttestationValue.Success(it, Padding)           }.toSet()   )) }
            callerNonce                  ?.let { add(Element. Single ( value =  AttestationValue.Success(it, CallerNonce)                  )) }
            minMacLength                 ?.let { add(Element. Single ( value =  AttestationValue.Success(it, MinMacLength)                 )) }
            ecCurve                      ?.let { add(Element. Single ( value =  AttestationValue.Success(it, ECCurve)                       )) }
            rsaPublicExponent            ?.let { add(Element. Single ( value =  AttestationValue.Success(it, RsaPublicExponent)             )) }
            mgfDigest                    ?.let { add(Element. SetOf  ( it.map { AttestationValue.Success(it, MgfDigest)         }.toSet()   )) }
            rollbackResistance           ?.let { add(Element. Single ( value =  AttestationValue.Success(it, RollbackResistance)            )) }
            earlyBootOnly                ?.let { add(Element. Single ( value =  AttestationValue.Success(it, EarlyBootOnly)                 )) }
            activeDateTime               ?.let { add(Element. Single ( value =  AttestationValue.Success(it, ActiveDateTime)                )) }
            originationExpireDateTime    ?.let { add(Element. Single ( value =  AttestationValue.Success(it, OriginationExpireDateTime)     )) }
            usageExpireDateTime          ?.let { add(Element. Single ( value =  AttestationValue.Success(it, UsageExpireDateTime)           )) }
            usageCountLimit              ?.let { add(Element. Single ( value =  AttestationValue.Success(it, UsageCountLimit)               )) }
            userSecureId                 ?.let { add(Element. Single ( value =  AttestationValue.Success(it, UserSecureId)                 )) }
            noAuthRequired               ?.let { add(Element. Single ( value =  AttestationValue.Success(it, NoAuthRequired)                )) }
            userAuthType                 ?.let { add(Element. Single ( value =  AttestationValue.Success(it, UserAuth)                      )) }
            authTimeout                  ?.let { add(Element. Single ( value =  AttestationValue.Success(it, AuthTimeout)                   )) }
            allowWhileOnBody             ?.let { add(Element. Single ( value =  AttestationValue.Success(it, AllowWhileOnBody)              )) }
            trustedUserPresenceRequired  ?.let { add(Element. Single ( value =  AttestationValue.Success(it, TrustedUserPresenceRequired)   )) }
            trustedConfirmationRequired  ?.let { add(Element. Single ( value =  AttestationValue.Success(it, TrustedConfirmationRequired)   )) }
            unlockedDeviceRequired       ?.let { add(Element. Single ( value =  AttestationValue.Success(it, UnlockedDeviceRequired)        )) }
            allApplications              ?.let { add(Element. Single ( value =  AttestationValue.Success(it, AllApplications)               )) }
            creationDateTime             ?.let { add(Element. Single ( value =  AttestationValue.Success(it, CreationDateTime)              )) }
            origin                       ?.let { add(Element. Single ( value =  AttestationValue.Success(it, Origin)                        )) }
            rollbackResistant            ?.let { add(Element. Single ( value =  AttestationValue.Success(it, RollbackResistent)             )) }
            rootOfTrust                  ?.let { add(Element. Single ( value =  AttestationValue.Success(it, RootOfTrust)                   )) }
            osVersion                    ?.let { add(Element. Single ( value =  AttestationValue.Success(it, OsVersion)                     )) }
            osPatchLevel                 ?.let { add(Element. Single ( value =  AttestationValue.Success(it, OsPatchLevel)                  )) }
            attestationApplicationId     ?.let { add(Element. Single ( value =  AttestationValue.Success(it, AttestationApplicationId)      )) }
            attestationIdBrand           ?.let { add(Element. Single ( value =  AttestationValue.Success(it, AttestationId.Brand)           )) }
            attestationIdDevice          ?.let { add(Element. Single ( value =  AttestationValue.Success(it, AttestationId.Device)          )) }
            attestationIdProduct         ?.let { add(Element. Single ( value =  AttestationValue.Success(it, AttestationId.Product)         )) }
            attestationIdSerial          ?.let { add(Element. Single ( value =  AttestationValue.Success(it, AttestationId.Serial)          )) }
            attestationIdImei            ?.let { add(Element. Single ( value =  AttestationValue.Success(it, AttestationId.Imei)            )) }
            attestationIdMeid            ?.let { add(Element. Single ( value =  AttestationValue.Success(it, AttestationId.Meid)            )) }
            attestationIdManufacturer    ?.let { add(Element. Single ( value =  AttestationValue.Success(it, AttestationId.Manufacturer)    )) }
            attestationIdModel           ?.let { add(Element. Single ( value =  AttestationValue.Success(it, AttestationId.Model)           )) }
            vendorPatchLevel             ?.let { add(Element. Single ( value =  AttestationValue.Success(it, PatchLevel.Vendor)             )) }
            bootPatchLevel               ?.let { add(Element. Single ( value =  AttestationValue.Success(it, PatchLevel.Boot)               )) }
            deviceUniqueAttestation      ?.let { add(Element. Single ( value =  AttestationValue.Success(it, DeviceUniqueAttestation)       )) }
            attestationIdSecondImei      ?.let { add(Element. Single ( value =  AttestationValue.Success(it, AttestationId.SecondImei)      )) }
            moduleHash                   ?.let { add(Element. Single ( value =  AttestationValue.Success(it, ModuleHash)                    )) }

            trailingProperties.forEach       { add(Element.Unknown(it)) }
            // @formatter:on
        }
    )

    val additionalProperties: List<Asn1Element>
        get() = elements.asSequence().mapNotNull { (it as? Element.Unknown)?.value }.toList()

    @Suppress("UNCHECKED_CAST")
    private fun <T> firstSingleByTag(tag: Tagged): T? =
        (elements.firstOrNull { it is Element.Single && it.value.tagged.explicitTag == tag.explicitTag } as? Element.Single)
            ?.value as? T

    @Suppress("UNCHECKED_CAST")
    private fun <T> firstSetByTag(tag: Tagged): Set<T>? =
        (elements.firstOrNull { it is Element.SetOf && it.value.first().tagged.explicitTag == tag.explicitTag } as? Element.SetOf)
            ?.value as? Set<T>

    // @formatter:off
    /**
     * Key purposes.
     *
     * Corresponds to the `Tag::PURPOSE` authorization tag, which uses a tag ID value of `1`.
     *
     * ASN.1: `purpose [1] EXPLICIT SET OF INTEGER OPTIONAL`.
     * Present in key attestation versions `1`, `2`, `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * See [KeyPurpose.Tag.explicitTag].
     */
    val purpose                    :  Set<AttestationValue<   KeyPurpose  >>?
                                      get() = firstSetByTag(  KeyPurpose  )

    /**
     * Key algorithm.
     *
     * Corresponds to the `Tag::ALGORITHM` authorization tag, which uses a tag ID value of `2`.
     *
     * ASN.1: `algorithm [2] EXPLICIT INTEGER OPTIONAL`.
     * Present in key attestation versions `1`, `2`, `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * See [Algorithm.Tag.explicitTag].
     */
    val algorithm                  :  AttestationValue<          Algorithm  >?
                                      get() = firstSingleByTag(  Algorithm  )

    /**
     * Key size (in bits).
     *
     * Corresponds to the `Tag::KEY_SIZE` authorization tag, which uses a tag ID value of `3`.
     *
     * ASN.1: `keySize [3] EXPLICIT INTEGER OPTIONAL`.
     * Present in key attestation versions `1`, `2`, `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * See [KeySize.Tag.explicitTag].
     */
    val keySize                    :  AttestationValue<          KeySize  >?
                                      get() = firstSingleByTag(  KeySize  )

    /**
     * Block modes.
     *
     * Corresponds to the `Tag::BLOCK_MODE` authorization tag, which uses a tag ID value of `4`.
     *
     * ASN.1: `blockMode [4] EXPLICIT SET OF INTEGER OPTIONAL`.
     * Present in key attestation versions `1`, `2`, `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * See [BlockMode.Tag.explicitTag].
     */
    val blockMode                  :  Set<AttestationValue<   BlockMode  >>?
                                      get() = firstSetByTag(  BlockMode  )

    /**
     * Digest modes.
     *
     * Corresponds to the `Tag::DIGEST` authorization tag, which uses a tag ID value of `5`.
     *
     * ASN.1: `digest [5] EXPLICIT SET OF INTEGER OPTIONAL`.
     * Present in key attestation versions `1`, `2`, `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * See [Digest.Tag.explicitTag].
     */
    val digest                     :  Set<AttestationValue<   Digest  >>?
                                      get() = firstSetByTag(  Digest  )

    /**
     * Padding modes.
     *
     * Corresponds to the `Tag::PADDING` authorization tag, which uses a tag ID value of `6`.
     *
     * ASN.1: `padding [6] EXPLICIT SET OF INTEGER OPTIONAL`.
     * Present in key attestation versions `1`, `2`, `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * See [Padding.Tag.explicitTag].
     */
    val padding                    :  Set<AttestationValue<   Padding  >>?
                                      get() = firstSetByTag(  Padding  )

    /**
     * Caller-provided nonce flag.
     *
     * Corresponds to the `Tag::CALLER_NONCE` authorization tag, which uses a tag ID value of `7`.
     *
     * ASN.1: `callerNonce [7] EXPLICIT NULL OPTIONAL`.
     * Present in key attestation versions `1`, `2`, `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * Note: in this API, presence/absence of this field is represented by `null` vs non-`null`.
     * See [CallerNonce.explicitTag].
     */
    val callerNonce                :  AttestationValue<          CallerNonce  >?
                                      get() = firstSingleByTag(  CallerNonce  )

    /**
     * Minimum MAC length (in bits).
     *
     * Corresponds to the `Tag::MIN_MAC_LENGTH` authorization tag, which uses a tag ID value of `8`.
     *
     * ASN.1: `minMacLength [8] EXPLICIT INTEGER OPTIONAL`.
     * Present in key attestation versions `1`, `2`, `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * See [MinMacLength.Tag.explicitTag].
     */
    val minMacLength               :  AttestationValue<          MinMacLength  >?
                                      get() = firstSingleByTag(  MinMacLength  )

    /**
     * Elliptic curve identifier.
     *
     * Corresponds to the `Tag::EC_CURVE` authorization tag, which uses a tag ID value of `10`.
     *
     * ASN.1: `ecCurve [10] EXPLICIT INTEGER OPTIONAL`.
     * Present in key attestation versions `1`, `2`, `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * See [ECCurve.Tag.explicitTag].
     */
    val ecCurve                    :  AttestationValue<          ECCurve  >?
                                      get() = firstSingleByTag(  ECCurve  )

    /**
     * RSA public exponent.
     *
     * Corresponds to the `Tag::RSA_PUBLIC_EXPONENT` authorization tag, which uses a tag ID value of `200`.
     *
     * ASN.1: `rsaPublicExponent [200] EXPLICIT INTEGER OPTIONAL`.
     * Present in key attestation versions `1`, `2`, `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * See [RsaPublicExponent.Tag.explicitTag].
     */
    val rsaPublicExponent          :  AttestationValue<          RsaPublicExponent  >?
                                      get() = firstSingleByTag(  RsaPublicExponent  )

    /**
     * RSA OAEP MGF digest.
     *
     * Corresponds to the `Tag::RSA_OAEP_MGF_DIGEST` authorization tag, which uses a tag ID value of `203`.
     *
     * ASN.1: `mgfDigest [203] EXPLICIT SET OF INTEGER OPTIONAL`.
     * Present in key attestation versions `100`, `200`, `300`, `400` (KeyMint only).
     *
     * See [MgfDigest.Tag.explicitTag].
     */
    val mgfDigest                  :  Set<AttestationValue<   MgfDigest  >>?
                                      get() = firstSetByTag(  MgfDigest  )

    /**
     * Rollback resistance.
     *
     * Corresponds to the `Tag::ROLLBACK_RESISTANCE` authorization tag, which uses a tag ID value of `303`.
     *
     * ASN.1: `rollbackResistance [303] EXPLICIT NULL OPTIONAL`.
     * Present in key attestation versions `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * Note: in this API, presence/absence of this field is represented by `null` vs non-`null`.
     * See [RollbackResistance.explicitTag].
     */
    val rollbackResistance         :  AttestationValue<          RollbackResistance  >?
                                      get() = firstSingleByTag(  RollbackResistance  )

    /**
     * Early-boot-only restriction.
     *
     * Corresponds to the `Tag::EARLY_BOOT_ONLY` authorization tag, which uses a tag ID value of `305`.
     *
     * ASN.1: `earlyBootOnly [305] EXPLICIT NULL OPTIONAL`.
     * Present in key attestation versions `4`, `100`, `200`, `300`, `400`.
     *
     * Note: in this API, presence/absence of this field is represented by `null` vs non-`null`.
     * See [EarlyBootOnly.explicitTag].
     */
    val earlyBootOnly              :  AttestationValue<          EarlyBootOnly  >?
                                      get() = firstSingleByTag(  EarlyBootOnly  )

    /**
     * Key validity "not before" timestamp.
     *
     * Corresponds to the `Tag::ACTIVE_DATETIME` authorization tag, which uses a tag ID value of `400`.
     *
     * ASN.1: `activeDateTime [400] EXPLICIT INTEGER OPTIONAL`, encoded as milliseconds since epoch.
     * Present in key attestation versions `1`, `2`, `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * See [ActiveDateTime.Tag.explicitTag].
     */
    val activeDateTime             :  AttestationValue<          ActiveDateTime  >?
                                      get() = firstSingleByTag(  ActiveDateTime  )

    /**
     * Key origination validity "not after" timestamp.
     *
     * Corresponds to the `Tag::ORIGINATION_EXPIRE_DATETIME` authorization tag, which uses a tag ID value of `401`.
     *
     * ASN.1: `originationExpireDateTime [401] EXPLICIT INTEGER OPTIONAL`, encoded as milliseconds since epoch.
     * Present in key attestation versions `1`, `2`, `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * See [OriginationExpireDateTime.Tag.explicitTag].
     */
    val originationExpireDateTime  :  AttestationValue<          OriginationExpireDateTime  >?
                                      get() = firstSingleByTag(  OriginationExpireDateTime  )

    /**
     * Key usage validity "not after" timestamp.
     *
     * Corresponds to the `Tag::USAGE_EXPIRE_DATETIME` authorization tag, which uses a tag ID value of `402`.
     *
     * ASN.1: `usageExpireDateTime [402] EXPLICIT INTEGER OPTIONAL`, encoded as milliseconds since epoch.
     * Present in key attestation versions `1`, `2`, `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * See [UsageExpireDateTime.Tag.explicitTag].
     */
    val usageExpireDateTime        :  AttestationValue<          UsageExpireDateTime  >?
                                      get() = firstSingleByTag(  UsageExpireDateTime  )

    /**
     * Key usage count limit.
     *
     * Corresponds to the `Tag::USAGE_COUNT_LIMIT` authorization tag, which uses a tag ID value of `405`.
     *
     * ASN.1: `usageCountLimit [405] EXPLICIT INTEGER OPTIONAL`.
     * Present in key attestation versions `4`, `100`, `200`, `300`, `400`.
     *
     * See [UsageCountLimit.Tag.explicitTag].
     */
    val usageCountLimit            :  AttestationValue<          UsageCountLimit  >?
                                      get() = firstSingleByTag(  UsageCountLimit  )

    /**
     * Secure user ID (SID).
     *
     * Corresponds to the `Tag::USER_SECURE_ID` authorization tag, which uses a tag ID value of `502`.
     *
     * ASN.1: `userSecureId [502] EXPLICIT INTEGER OPTIONAL`.
     * Present in key attestation versions `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * See [UserSecureId.Tag.explicitTag].
     */
    val userSecureId               :  AttestationValue<          UserSecureId  >?
                                      get() = firstSingleByTag(  UserSecureId  )

    /**
     * No-authentication-required flag.
     *
     * Corresponds to the `Tag::NO_AUTH_REQUIRED` authorization tag, which uses a tag ID value of `503`.
     *
     * ASN.1: `noAuthRequired [503] EXPLICIT NULL OPTIONAL`.
     * Present in key attestation versions `1`, `2`, `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * Note: in this API, presence/absence of this field is represented by `null` vs non-`null`.
     * See [NoAuthRequired.explicitTag].
     */
    val noAuthRequired             :  AttestationValue<          NoAuthRequired  >?
                                      get() = firstSingleByTag(  NoAuthRequired  )

    /**
     * Hardware authenticator type (user authentication type).
     *
     * Corresponds to the `Tag::USER_AUTH_TYPE` authorization tag, which uses a tag ID value of `504`.
     *
     * ASN.1: `userAuthType [504] EXPLICIT INTEGER OPTIONAL`.
     * Present in key attestation versions `1`, `2`, `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * See [UserAuth.Tag.explicitTag].
     */
    val userAuthType               :  AttestationValue<          UserAuth  >?
                                      get() = firstSingleByTag(  UserAuth  )

    /**
     * User authentication timeout.
     *
     * Corresponds to the `Tag::AUTH_TIMEOUT` authorization tag, which uses a tag ID value of `505`.
     *
     * ASN.1: `authTimeout [505] EXPLICIT INTEGER OPTIONAL`, encoded as seconds.
     * Present in key attestation versions `1`, `2`, `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * See [AuthTimeout.Tag.explicitTag].
     */
    val authTimeout                :  AttestationValue<          AuthTimeout  >?
                                      get() = firstSingleByTag(  AuthTimeout  )

    /**
     * Allow-while-on-body flag.
     *
     * Corresponds to the `Tag::ALLOW_WHILE_ON_BODY` authorization tag, which uses a tag ID value of `506`.
     *
     * ASN.1: `allowWhileOnBody [506] EXPLICIT NULL OPTIONAL`.
     * Present in key attestation versions `1`, `2`, `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * Note: in this API, presence/absence of this field is represented by `null` vs non-`null`.
     * See [AllowWhileOnBody.explicitTag].
     */
    val allowWhileOnBody           :  AttestationValue<          AllowWhileOnBody  >?
                                      get() = firstSingleByTag(  AllowWhileOnBody  )

    /**
     * Trusted user presence required flag.
     *
     * Corresponds to the `Tag::TRUSTED_USER_PRESENCE_REQUIRED` authorization tag, which uses a tag ID value of `507`.
     *
     * ASN.1: `trustedUserPresenceRequired [507] EXPLICIT NULL OPTIONAL`.
     * Present in key attestation versions `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * Note: in this API, presence/absence of this field is represented by `null` vs non-`null`.
     * See [TrustedUserPresenceRequired.explicitTag].
     */
    val trustedUserPresenceRequired:  AttestationValue<          TrustedUserPresenceRequired  >?
                                      get() = firstSingleByTag(  TrustedUserPresenceRequired  )

    /**
     * Trusted confirmation required flag.
     *
     * Corresponds to the `Tag::TRUSTED_CONFIRMATION_REQUIRED` authorization tag, which uses a tag ID value of `508`.
     *
     * ASN.1: `trustedConfirmationRequired [508] EXPLICIT NULL OPTIONAL`.
     * Present in key attestation versions `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * Note: in this API, presence/absence of this field is represented by `null` vs non-`null`.
     * See [TrustedConfirmationRequired.explicitTag].
     */
    val trustedConfirmationRequired:  AttestationValue<          TrustedConfirmationRequired  >?
                                      get() = firstSingleByTag(  TrustedConfirmationRequired  )

    /**
     * Unlocked device required flag.
     *
     * Corresponds to the `Tag::UNLOCKED_DEVICE_REQUIRED` authorization tag, which uses a tag ID value of `509`.
     *
     * ASN.1: `unlockedDeviceRequired [509] EXPLICIT NULL OPTIONAL`.
     * Present in key attestation versions `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * Note: in this API, presence/absence of this field is represented by `null` vs non-`null`.
     * See [UnlockedDeviceRequired.explicitTag].
     */
    val unlockedDeviceRequired     :  AttestationValue<          UnlockedDeviceRequired  >?
                                      get() = firstSingleByTag(  UnlockedDeviceRequired  )

    /**
     * "All applications" flag (legacy / keymaster).
     *
     * This tag is part of older schema versions and is not present in KeyMint (attestation versions `100+`).
     *
     * Corresponds to the legacy `KM_TAG_ALL_APPLICATIONS` / `Tag::ALL_APPLICATIONS` authorization tag, which uses a
     * tag ID value of `600`.
     *
     * ASN.1: `allApplications [600] EXPLICIT NULL OPTIONAL`.
     * Present in key attestation versions `1`, `2` only.
     *
     * Note: in this API, presence/absence of this field is represented by `null` vs non-`null`.
     * See [AllApplications.explicitTag].
     */
    val allApplications            :  AttestationValue<          AllApplications  >?
                                      get() = firstSingleByTag(  AllApplications  )

    /**
     * Key creation timestamp.
     *
     * Corresponds to the `Tag::CREATION_DATETIME` authorization tag, which uses a tag ID value of `701`.
     *
     * ASN.1: `creationDateTime [701] EXPLICIT INTEGER OPTIONAL`, encoded as milliseconds since epoch.
     * Present in key attestation versions `1`, `2`, `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * See [CreationDateTime.Tag.explicitTag].
     */
    val creationDateTime           :  AttestationValue<          CreationDateTime  >?
                                      get() = firstSingleByTag(  CreationDateTime  )

    /**
     * Key origin.
     *
     * Corresponds to the `Tag::ORIGIN` authorization tag, which uses a tag ID value of `702`.
     *
     * ASN.1: `origin [702] EXPLICIT INTEGER OPTIONAL`.
     * Present in key attestation versions `1`, `2`, `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * See [Origin.Tag.explicitTag].
     */
    val origin                     :  AttestationValue<          Origin  >?
                                      get() = firstSingleByTag(  Origin  )

    /**
     * Legacy rollback-resistant flag (keymaster attestation versions 1–2).
     *
     * This is the predecessor of [rollbackResistance] (`[303]`), and is not present in newer schemas.
     *
     * Corresponds to the legacy `KM_TAG_ROLLBACK_RESISTANT` authorization tag, which uses a tag ID value of `703`.
     *
     * ASN.1: `rollbackResistant [703] EXPLICIT NULL OPTIONAL`.
     * Present in key attestation versions `1`, `2` only.
     *
     * Note: in this API, presence/absence of this field is represented by `null` vs non-`null`.
     * See [RollbackResistent.explicitTag].
     */
    val rollbackResistant          :  AttestationValue<          RollbackResistent  >?
                                      get() = firstSingleByTag(  RollbackResistent  )

    /**
     * Root of trust information (verified boot state, device lock state, etc).
     *
     * Corresponds to the `Tag::ROOT_OF_TRUST` authorization tag, which uses a tag ID value of `704`.
     *
     * ASN.1: `rootOfTrust [704] EXPLICIT SEQUENCE OPTIONAL`.
     * Present in key attestation versions `1`, `2`, `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * See [RootOfTrust.Tag.explicitTag].
     */
    val rootOfTrust                :  AttestationValue<          RootOfTrust  >?
                                      get() = firstSingleByTag(  RootOfTrust  )

    /**
     * Operating system version.
     *
     * Corresponds to the `Tag::OS_VERSION` authorization tag, which uses a tag ID value of `705`.
     *
     * ASN.1: `osVersion [705] EXPLICIT INTEGER OPTIONAL`.
     * Present in key attestation versions `1`, `2`, `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * See [OsVersion.Tag.explicitTag].
     */
    val osVersion                  :  AttestationValue<          OsVersion  >?
                                      get() = firstSingleByTag(  OsVersion  )

    /**
     * Operating system patch level.
     *
     * Corresponds to the `Tag::OS_PATCHLEVEL` authorization tag, which uses a tag ID value of `706`.
     *
     * ASN.1: `osPatchLevel [706] EXPLICIT INTEGER OPTIONAL`.
     * Present in key attestation versions `1`, `2`, `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * See [OsPatchLevel.Tag.explicitTag].
     */
    val osPatchLevel               :  AttestationValue<          OsPatchLevel  >?
                                      get() = firstSingleByTag(  OsPatchLevel  )

    /**
     * Attestation application ID.
     *
     * Corresponds to the `Tag::ATTESTATION_APPLICATION_ID` authorization tag, which uses a tag ID value of `709`.
     *
     * ASN.1: `attestationApplicationId [709] EXPLICIT OCTET STRING OPTIONAL`.
     * Present in key attestation versions `2`, `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * See [AttestationApplicationId.Tag.explicitTag].
     */
    val attestationApplicationId   :  AttestationValue<          AttestationApplicationId  >?
                                      get() = firstSingleByTag(  AttestationApplicationId  )

    /**
     * Device brand.
     *
     * Corresponds to the `Tag::ATTESTATION_ID_BRAND` authorization tag, which uses a tag ID value of `710`.
     *
     * ASN.1: `attestationIdBrand [710] EXPLICIT OCTET STRING OPTIONAL`.
     * Present in key attestation versions `2`, `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * See [AttestationId.Brand.Tag.explicitTag].
     */
    val attestationIdBrand         :  AttestationValue<          AttestationId.Brand  >?
                                      get() = firstSingleByTag(  AttestationId.Brand  )

    /**
     * Device name.
     *
     * Corresponds to the `Tag::ATTESTATION_ID_DEVICE` authorization tag, which uses a tag ID value of `711`.
     *
     * ASN.1: `attestationIdDevice [711] EXPLICIT OCTET STRING OPTIONAL`.
     * Present in key attestation versions `2`, `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * See [AttestationId.Device.Tag.explicitTag].
     */
    val attestationIdDevice        :  AttestationValue<          AttestationId.Device  >?
                                      get() = firstSingleByTag(  AttestationId.Device  )

    /**
     * Product name.
     *
     * Corresponds to the `Tag::ATTESTATION_ID_PRODUCT` authorization tag, which uses a tag ID value of `712`.
     *
     * ASN.1: `attestationIdProduct [712] EXPLICIT OCTET STRING OPTIONAL`.
     * Present in key attestation versions `2`, `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * See [AttestationId.Product.Tag.explicitTag].
     */
    val attestationIdProduct       :  AttestationValue<          AttestationId.Product  >?
                                      get() = firstSingleByTag(  AttestationId.Product  )

    /**
     * Device serial number.
     *
     * Corresponds to the `Tag::ATTESTATION_ID_SERIAL` authorization tag, which uses a tag ID value of `713`.
     *
     * ASN.1: `attestationIdSerial [713] EXPLICIT OCTET STRING OPTIONAL`.
     * Present in key attestation versions `2`, `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * See [AttestationId.Serial.Tag.explicitTag].
     */
    val attestationIdSerial        :  AttestationValue<          AttestationId.Serial  >?
                                      get() = firstSingleByTag(  AttestationId.Serial  )

    /**
     * IMEI (first slot).
     *
     * Corresponds to the `Tag::ATTESTATION_ID_IMEI` authorization tag, which uses a tag ID value of `714`.
     *
     * ASN.1: `attestationIdImei [714] EXPLICIT OCTET STRING OPTIONAL`.
     * Present in key attestation versions `2`, `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * See [AttestationId.Imei.Tag.explicitTag].
     */
    val attestationIdImei          :  AttestationValue<          AttestationId.Imei  >?
                                      get() = firstSingleByTag(  AttestationId.Imei  )

    /**
     * MEID.
     *
     * Corresponds to the `Tag::ATTESTATION_ID_MEID` authorization tag, which uses a tag ID value of `715`.
     *
     * ASN.1: `attestationIdMeid [715] EXPLICIT OCTET STRING OPTIONAL`.
     * Present in key attestation versions `2`, `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * See [AttestationId.Meid.Tag.explicitTag].
     */
    val attestationIdMeid          :  AttestationValue<          AttestationId.Meid  >?
                                      get() = firstSingleByTag(  AttestationId.Meid  )

    /**
     * Manufacturer name.
     *
     * Corresponds to the `Tag::ATTESTATION_ID_MANUFACTURER` authorization tag, which uses a tag ID value of `716`.
     *
     * ASN.1: `attestationIdManufacturer [716] EXPLICIT OCTET STRING OPTIONAL`.
     * Present in key attestation versions `2`, `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * See [AttestationId.Manufacturer.Tag.explicitTag].
     */
    val attestationIdManufacturer  :  AttestationValue<          AttestationId.Manufacturer  >?
                                      get() = firstSingleByTag(  AttestationId.Manufacturer  )

    /**
     * Device model.
     *
     * Corresponds to the `Tag::ATTESTATION_ID_MODEL` authorization tag, which uses a tag ID value of `717`.
     *
     * ASN.1: `attestationIdModel [717] EXPLICIT OCTET STRING OPTIONAL`.
     * Present in key attestation versions `2`, `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * See [AttestationId.Model.Tag.explicitTag].
     */
    val attestationIdModel         :  AttestationValue<          AttestationId.Model  >?
                                      get() = firstSingleByTag(  AttestationId.Model  )

    /**
     * Vendor patch level.
     *
     * Corresponds to the `Tag::VENDOR_PATCHLEVEL` authorization tag, which uses a tag ID value of `718`.
     *
     * ASN.1: `vendorPatchLevel [718] EXPLICIT INTEGER OPTIONAL`.
     * Present in key attestation versions `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * See [PatchLevel.Vendor.Tag.explicitTag].
     */
    val vendorPatchLevel           :  AttestationValue<          PatchLevel.Vendor  >?
                                      get() = firstSingleByTag(  PatchLevel.Vendor  )

    /**
     * Boot patch level.
     *
     * Corresponds to the `Tag::BOOT_PATCHLEVEL` authorization tag, which uses a tag ID value of `719`.
     *
     * ASN.1: `bootPatchLevel [719] EXPLICIT INTEGER OPTIONAL`.
     * Present in key attestation versions `3`, `4`, `100`, `200`, `300`, `400`.
     *
     * See [PatchLevel.Boot.Tag.explicitTag].
     */
    val bootPatchLevel             :  AttestationValue<          PatchLevel.Boot  >?
                                      get() = firstSingleByTag(  PatchLevel.Boot  )

    /**
     * Device-unique attestation flag.
     *
     * Corresponds to the `Tag::DEVICE_UNIQUE_ATTESTATION` authorization tag, which uses a tag ID value of `720`.
     *
     * ASN.1: `deviceUniqueAttestation [720] EXPLICIT NULL OPTIONAL`.
     * Present in key attestation versions `4`, `100`, `200`, `300`, `400`.
     *
     * Note: in this API, presence/absence of this field is represented by `null` vs non-`null`.
     * See [DeviceUniqueAttestation.explicitTag].
     */
    val deviceUniqueAttestation    :  AttestationValue<          DeviceUniqueAttestation  >?
                                      get() = firstSingleByTag(  DeviceUniqueAttestation  )

    /**
     * IMEI (second slot).
     *
     * Corresponds to the `Tag::ATTESTATION_ID_SECOND_IMEI` authorization tag, which uses a tag ID value of `723`.
     *
     * ASN.1: `attestationIdSecondImei [723] EXPLICIT OCTET STRING OPTIONAL`.
     * Present in key attestation versions `300`, `400` only.
     *
     * See [AttestationId.SecondImei.Tag.explicitTag].
     */
    val attestationIdSecondImei    :  AttestationValue<          AttestationId.SecondImei  >?
                                      get() = firstSingleByTag(  AttestationId.SecondImei  )

    /**
     * Module hash.
     *
     * Corresponds to the `Tag::MODULE_HASH` authorization tag, which uses a tag ID value of `724`.
     *
     * ASN.1: `moduleHash [724] EXPLICIT OCTET STRING OPTIONAL`.
     * Present in key attestation version `400` only.
     *
     * See [ModuleHash.Tag.explicitTag].
     */
    val moduleHash                 :  AttestationValue<          ModuleHash  >?
                                      get() = firstSingleByTag(  ModuleHash  )
    // @formatter:on

    init {
        purpose?.let { require(it.isNotEmpty()) }
        blockMode?.let { require(it.isNotEmpty()) }
        digest?.let { require(it.isNotEmpty()) }
        padding?.let { require(it.isNotEmpty()) }
        mgfDigest?.let { require(it.isNotEmpty()) }
    }

    /**
     * Useful for debugging, but too strict in reality
     */
    fun versionCheck(attestationVersion: Int) {
        if (attestationVersion < 400) {
            require(moduleHash == null)
        }
        if (attestationVersion < 300) {
            require(attestationIdSecondImei == null)
        }
        // no changes from 100 to 200
        if (attestationVersion < 100) {
            require(mgfDigest == null) // isNullOrEmpty ? TODO
            require(usageCountLimit == null)
        }
        if (attestationVersion > 4) {
            require(allApplications == null)
        }
        if (attestationVersion < 4) {
            require(earlyBootOnly == null)
            require(deviceUniqueAttestation == null)
        }
        if (attestationVersion < 3) {
            require(rollbackResistance == null)
            require(trustedUserPresenceRequired == null)
            require(trustedConfirmationRequired == null)
            require(unlockedDeviceRequired == null)
            require(vendorPatchLevel == null)
            require(bootPatchLevel == null)
            require(userSecureId == null)
            //if(rootOfTrust != null) require(rootOfTrust.getOrNull().verifiedBootHash == 0) // TODO decoding must be changed!!
        }
        if (attestationVersion > 2) {
            require(rollbackResistant == null)
        }
        if (attestationVersion < 2) {
            require(attestationApplicationId == null)
            require(attestationIdBrand == null)
            require(attestationIdDevice == null)
            require(attestationIdProduct == null)
            require(attestationIdSerial == null)
            require(attestationIdImei == null)
            require(attestationIdMeid == null)
            require(attestationIdManufacturer == null)
            require(attestationIdModel == null)
        }
        // TODO: only provide getter in right versions?
    }

    override fun encodeToTlv() = Asn1.Sequence {
        elements.forEach { element ->
            when (element) {
                is Element.Single -> add(element.value)
                is Element.SetOf -> add(element.value)
                is Element.Unknown -> +element.value
            }
        }
    }

    companion object : Asn1Decodable<Asn1Sequence, AuthorizationList> {
        override fun doDecode(src: Asn1Sequence): AuthorizationList {
            val elements = buildList {
                for (child in src.children) {
                    val explicitlyTagged = child as? Asn1ExplicitlyTagged ?: run {
                        add(Element.Unknown(child))
                        continue
                    }

                    val inner = explicitlyTagged.children.singleOrNull() ?: run {
                        add(Element.Unknown(child))
                        continue
                    }

                    // @formatter:off
                    val added = when (explicitlyTagged.tag) {
                        Asn1.ExplicitTag(KeyPurpose.explicitTag)                  -> (inner as? Asn1Set)        ?.let { KeyPurpose                  .decodeSetElement<KeyPurpose>(it) }?.also { add(Element.SetOf(it)) }
                        Asn1.ExplicitTag(Algorithm.explicitTag)                   -> add(Element.Single(        value = Algorithm                   .decodeElement<Algorithm>(inner)))
                        Asn1.ExplicitTag(KeySize.explicitTag)                     -> add(Element.Single(        value = KeySize                     .decodeElement<KeySize>(inner)))
                        Asn1.ExplicitTag(BlockMode.explicitTag)                   -> (inner as? Asn1Set)        ?.let { BlockMode                  .decodeSetElement<BlockMode>(it) }?.also { add(Element.SetOf(it)) }
                        Asn1.ExplicitTag(Digest.explicitTag)                      -> (inner as? Asn1Set)        ?.let { Digest                      .decodeSetElement<Digest>(it) }?.also { add(Element.SetOf(it)) }
                        Asn1.ExplicitTag(Padding.explicitTag)                     -> (inner as? Asn1Set)        ?.let { Padding                     .decodeSetElement<Padding>(it) }?.also { add(Element.SetOf(it)) }
                        Asn1.ExplicitTag(CallerNonce.explicitTag)                 -> (inner as? Asn1Primitive)  ?.let { add(Element.Single(value =  CallerNonce                 .decodeNullElement(it))) }
                        Asn1.ExplicitTag(MinMacLength.explicitTag)                -> add(Element.Single(        value = MinMacLength                .decodeElement<MinMacLength>(inner)))
                        Asn1.ExplicitTag(ECCurve.explicitTag)                     -> add(Element.Single(        value = ECCurve                     .decodeElement<ECCurve>(inner)))
                        Asn1.ExplicitTag(RsaPublicExponent.explicitTag)           -> add(Element.Single(        value = RsaPublicExponent           .decodeElement<RsaPublicExponent>(inner)))
                        Asn1.ExplicitTag(MgfDigest.explicitTag)                   -> (inner as? Asn1Set)        ?.let { MgfDigest                   .decodeSetElement<MgfDigest>(it) }?.also { add(Element.SetOf(it)) }
                        Asn1.ExplicitTag(RollbackResistance.explicitTag)          -> (inner as? Asn1Primitive)  ?.let { add(Element.Single(value =  RollbackResistance.decodeNullElement(it))) }
                        Asn1.ExplicitTag(EarlyBootOnly.explicitTag)               -> (inner as? Asn1Primitive)  ?.let { add(Element.Single(value =  EarlyBootOnly.decodeNullElement(it))) }
                        Asn1.ExplicitTag(ActiveDateTime.explicitTag)              -> add(Element.Single(        value = ActiveDateTime              .decodeElement<ActiveDateTime>(inner)))
                        Asn1.ExplicitTag(OriginationExpireDateTime.explicitTag)   -> add(Element.Single(        value = OriginationExpireDateTime   .decodeElement<OriginationExpireDateTime>(inner)))
                        Asn1.ExplicitTag(UsageExpireDateTime.explicitTag)         -> add(Element.Single(        value = UsageExpireDateTime         .decodeElement<UsageExpireDateTime>(inner)))
                        Asn1.ExplicitTag(UsageCountLimit.explicitTag)             -> add(Element.Single(        value = UsageCountLimit             .decodeElement<UsageCountLimit>(inner)))
                        Asn1.ExplicitTag(UserSecureId.explicitTag)                -> add(Element.Single(        value = UserSecureId                .decodeElement<UserSecureId>(inner)))
                        Asn1.ExplicitTag(NoAuthRequired.explicitTag)              -> (inner as? Asn1Primitive)  ?.let { add(Element.Single(value =  NoAuthRequired.decodeNullElement(it))) }
                        Asn1.ExplicitTag(UserAuth.explicitTag)                    -> add(Element.Single(        value = UserAuth                    .decodeElement<UserAuth>(inner)))
                        Asn1.ExplicitTag(AuthTimeout.explicitTag)                 -> add(Element.Single(        value = AuthTimeout                 .decodeElement<AuthTimeout>(inner)))
                        Asn1.ExplicitTag(AllowWhileOnBody.explicitTag)            -> (inner as? Asn1Primitive)  ?.let { add(Element.Single(value =  AllowWhileOnBody.decodeNullElement(it))) }
                        Asn1.ExplicitTag(TrustedUserPresenceRequired.explicitTag) -> (inner as? Asn1Primitive)  ?.let { add(Element.Single(value =  TrustedUserPresenceRequired.decodeNullElement(it))) }
                        Asn1.ExplicitTag(TrustedConfirmationRequired.explicitTag) -> (inner as? Asn1Primitive)  ?.let { add(Element.Single(value =  TrustedConfirmationRequired.decodeNullElement(it))) }
                        Asn1.ExplicitTag(UnlockedDeviceRequired.explicitTag)      -> (inner as? Asn1Primitive)  ?.let { add(Element.Single(value =  UnlockedDeviceRequired.decodeNullElement(it))) }
                        Asn1.ExplicitTag(AllApplications.explicitTag)             -> (inner as? Asn1Primitive)  ?.let { add(Element.Single(value =  AllApplications.decodeNullElement(it))) }
                        Asn1.ExplicitTag(CreationDateTime.explicitTag)            -> add(Element.Single(        value = CreationDateTime            .decodeElement<CreationDateTime>(inner)))
                        Asn1.ExplicitTag(Origin.explicitTag)                      -> add(Element.Single(        value = Origin                      .decodeElement<Origin>(inner)))
                        Asn1.ExplicitTag(RollbackResistent.explicitTag)           -> (inner as? Asn1Primitive)  ?.let { add(Element.Single(value =  RollbackResistent.decodeNullElement(it))) }
                        Asn1.ExplicitTag(RootOfTrust.explicitTag)                 -> add(Element.Single(        value = RootOfTrust                 .decodeElement<RootOfTrust>(inner)))
                        Asn1.ExplicitTag(OsVersion.explicitTag)                   -> add(Element.Single(        value = OsVersion                   .decodeElement<OsVersion>(inner)))
                        Asn1.ExplicitTag(OsPatchLevel.explicitTag)                -> add(Element.Single(        value = OsPatchLevel                .decodeElement<OsPatchLevel>(inner)))
                        Asn1.ExplicitTag(AttestationApplicationId.explicitTag)    -> add(Element.Single(        value = AttestationApplicationId    .decodeElement<AttestationApplicationId>(inner)))
                        Asn1.ExplicitTag(AttestationId.Brand.explicitTag)         -> add(Element.Single(        value = AttestationId.Brand         .decodeElement<AttestationId.Brand>(inner)))
                        Asn1.ExplicitTag(AttestationId.Device.explicitTag)        -> add(Element.Single(        value = AttestationId.Device        .decodeElement<AttestationId.Device>(inner)))
                        Asn1.ExplicitTag(AttestationId.Product.explicitTag)       -> add(Element.Single(        value = AttestationId.Product       .decodeElement<AttestationId.Product>(inner)))
                        Asn1.ExplicitTag(AttestationId.Serial.explicitTag)        -> add(Element.Single(        value = AttestationId.Serial        .decodeElement<AttestationId.Serial>(inner)))
                        Asn1.ExplicitTag(AttestationId.Imei.explicitTag)          -> add(Element.Single(        value = AttestationId.Imei          .decodeElement<AttestationId.Imei>(inner)))
                        Asn1.ExplicitTag(AttestationId.Meid.explicitTag)          -> add(Element.Single(        value = AttestationId.Meid          .decodeElement<AttestationId.Meid>(inner)))
                        Asn1.ExplicitTag(AttestationId.Manufacturer.explicitTag)  -> add(Element.Single(        value = AttestationId.Manufacturer  .decodeElement<AttestationId.Manufacturer>(inner)))
                        Asn1.ExplicitTag(AttestationId.Model.explicitTag)         -> add(Element.Single(        value = AttestationId.Model         .decodeElement<AttestationId.Model>(inner)))
                        Asn1.ExplicitTag(PatchLevel.Vendor.explicitTag)           -> add(Element.Single(        value = PatchLevel.Vendor           .decodeElement<PatchLevel.Vendor>(inner)))
                        Asn1.ExplicitTag(PatchLevel.Boot.explicitTag)             -> add(Element.Single(        value = PatchLevel.Boot             .decodeElement<PatchLevel.Boot>(inner)))
                        Asn1.ExplicitTag(DeviceUniqueAttestation.explicitTag)     -> (inner as? Asn1Primitive)  ?.let { add(Element.Single(value =  DeviceUniqueAttestation.decodeNullElement(it))) }
                        Asn1.ExplicitTag(AttestationId.SecondImei.explicitTag)    -> add(Element.Single(        value = AttestationId.SecondImei    .decodeElement<AttestationId.SecondImei>(inner)))
                        Asn1.ExplicitTag(ModuleHash.explicitTag)                  -> add(Element.Single(        value = ModuleHash                  .decodeElement<ModuleHash>(inner)))

                        else -> null
                    }
                    // @formatter:on

                    if (added == null) add(Element.Unknown(child))

                }
            }

            return AuthorizationList(elements)
        }

        private inline fun <reified D : Asn1Encodable<Asn1Element>> Tagged.decodeElement(
            element: Asn1Element
        ): AttestationValue<*> {
            @Suppress("UNCHECKED_CAST")
            return (this as Asn1Decodable<Asn1Element, D>).decodeFromTlvSafe(src = element).fold(
                onSuccess = { AttestationValue.Success(it, this) },
                onFailure = { AttestationValue.Failure(D::class.simpleName!!, this, element) }
            )
        }

        private inline fun <reified D : Asn1Encodable<Asn1Element>> Tagged.decodeSetElement(
            element: Asn1Set
        ): Set<AttestationValue<*>>? {
            @Suppress("UNCHECKED_CAST")
            val values = LinkedHashSet<AttestationValue<*>>(element.children.size)
            for (child in element.children) {
                val primitiveOrNull = catchingUnwrapped { child.asPrimitive() }.getOrNull()
                val decoded = if (primitiveOrNull == null) {
                    AttestationValue.Failure(D::class.simpleName!!, this, child)
                } else {
                    (this as Asn1Decodable<Asn1Element, D>).decodeFromTlvSafe(primitiveOrNull).fold(
                        onSuccess = { AttestationValue.Success(it, this) },
                        onFailure = { AttestationValue.Failure(D::class.simpleName!!, this, child) }
                    )
                }
                values += decoded
            }

            if (values.isEmpty()) return null
            return OrderPreservingSet(values)
        }

        private fun <A> A.decodeNullElement(element: Asn1Primitive): AttestationValue<*>
                where A : Asn1Encodable<Asn1Primitive>, A : Tagged =
            catchingUnwrapped { element.readNull() }.fold(
                onSuccess = { AttestationValue.Success(this, this) },
                onFailure = { AttestationValue.Failure(this::class.simpleName!!, this, element) }
            )
    }

    private fun Asn1TreeBuilder.add(element: Set<Tagged.WithTag<*>>?) {
        element?.let { +it.encode() }
    }

    private fun Asn1TreeBuilder.add(element: Tagged.WithTag<*>?) {
        element?.let { +Asn1.ExplicitlyTagged(it.tagged.explicitTag) { +it.encodeToTlv() } }
    }

    private fun Asn1TreeBuilder.add(element: Tagged?) {
        element?.let { +Asn1.ExplicitlyTagged(it.explicitTag) { +Asn1.Null() } }
    }

    private val Set<Tagged.WithTag<*>>.explicitTag get() = first().tagged.explicitTag
    private fun Set<Tagged.WithTag<*>>.encode() = Asn1.ExplicitlyTagged(explicitTag) {
        if (this@encode is OrderPreservingSet<*>) {
            +Asn1Set.fromPresorted(map { it.encodeToTlv() })
        } else {
            +Asn1.SetOf { forEach { +it } }
        }
    }


    @OptIn(ExperimentalStdlibApi::class)
    override fun toString(): String {
        return "AuthorizationList(" +
                "purpose=$purpose, " +
                "algorithm=$algorithm, " +
                "keySize=$keySize, " +
                "blockMode=$blockMode, " +
                "digest=$digest, " +
                "padding=$padding, " +
                "callerNonce=${callerNonce != null}, " +
                "minMacLength=$minMacLength, " +
                "ecCurve=$ecCurve, " +
                "rsaPublicExponent=$rsaPublicExponent, " +
                "mgfDigest=$mgfDigest, " +
                "rollbackResistance=${rollbackResistance != null}, " +
                "earlyBootOnly=${earlyBootOnly != null}, " +
                "activeDateTime=$activeDateTime, " +
                "originationExpireDateTime=$originationExpireDateTime, " +
                "usageExpireDateTime=$usageExpireDateTime, " +
                "usageCountLimit=$usageCountLimit, " +
                "userSecureId=$userSecureId, " +
                "noAuthRequired=${noAuthRequired != null}, " +
                "userAuthType=$userAuthType, " +
                "authTimeout=$authTimeout, " +
                "allowWhileOnBody=${allowWhileOnBody != null}, " +
                "trustedUserPresenceRequired=${trustedUserPresenceRequired != null}, " +
                "trustedConfirmationRequired=${trustedConfirmationRequired != null}, " +
                "unlockedDeviceRequired=${unlockedDeviceRequired != null}, " +
                "allApplications=${allApplications != null}, " +
                "creationDateTime=$creationDateTime, " +
                "origin=$origin, " +
                "rollbackResistant=$rollbackResistant, " +
                "rootOfTrust=$rootOfTrust, " +
                "osVersion=$osVersion, " +
                "osPatchLevel=$osPatchLevel, " +
                "attestationApplicationId=$attestationApplicationId, " +
                "attestationIdBrand=$attestationIdBrand, " +
                "attestationIdDevice=$attestationIdDevice, " +
                "attestationIdProduct=$attestationIdProduct, " +
                "attestationIdSerial=$attestationIdSerial, " +
                "attestationIdImei=$attestationIdImei, " +
                "attestationIdMeid=$attestationIdMeid, " +
                "attestationIdManufacturer=$attestationIdManufacturer, " +
                "attestationIdModel=$attestationIdModel, " +
                "vendorPatchLevel=$vendorPatchLevel, " +
                "bootPatchLevel=$bootPatchLevel, " +
                "deviceUniqueAttestation=${deviceUniqueAttestation != null}, " +
                "attestationIdSecondImei=$attestationIdSecondImei, " +
                "moduleHash=$moduleHash," +
                ")"
    }

    // AuthorizationList.prettyPrint
    @OptIn(ExperimentalStdlibApi::class)
    override fun doPrettyPrint(indent: String): String {
        val fieldIndent = indent + "  "
        val valueIndent = indent + "    "

        fun AttestationValue<*>.render(indent: String): String = doPrettyPrint(indent)

        fun StringBuilder.appendSingle(name: String, value: AttestationValue<*>?) {
            append(fieldIndent).append(name).append(" = ")
            if (value == null) {
                append("null\n")
                return
            }

            // try inline if it renders to a single line
            val rendered = value.render(valueIndent)
            val lines = rendered.lines()
            if (lines.size == 1) {
                append(lines.first().trimStart()).append('\n')
            } else {
                append('\n')
                append(rendered).append('\n')
            }
        }

        fun StringBuilder.appendSet(name: String, values: Set<AttestationValue<*>>?) {
            append(fieldIndent).append(name).append(" = ")
            if (values.isNullOrEmpty()) {
                append("null\n")
                return
            }
            append("[\n")
            values.forEach { v ->
                val rendered = v.render(valueIndent)
                val lines = rendered.lines()
                if (lines.size == 1) {
                    append(valueIndent).append("- ").append(lines.first().trimStart()).append('\n')
                } else {
                    append(valueIndent).append("-\n")
                    append(rendered).append('\n')
                }
            }
            append(fieldIndent).append("]\n")
        }

        fun StringBuilder.appendBool(name: String, present: Boolean) {
            append(fieldIndent).append(name).append(" = ").append(present).append('\n')
        }

        return buildString {
            append(indent).append("AuthorizationList(\n")

            appendSet("purpose", purpose as Set<AttestationValue<*>>?)
            appendSingle("algorithm", algorithm)
            appendSingle("keySize", keySize)
            appendSet("blockMode", blockMode as Set<AttestationValue<*>>?)
            appendSet("digest", digest as Set<AttestationValue<*>>?)
            appendSet("padding", padding as Set<AttestationValue<*>>?)
            appendBool("callerNonce", callerNonce != null)
            appendSingle("minMacLength", minMacLength)
            appendSingle("ecCurve", ecCurve)
            appendSingle("rsaPublicExponent", rsaPublicExponent)
            appendSet("mgfDigest", mgfDigest as Set<AttestationValue<*>>?)

            appendBool("rollbackResistance", rollbackResistance != null)
            appendBool("earlyBootOnly", earlyBootOnly != null)

            appendSingle("activeDateTime", activeDateTime)
            appendSingle("originationExpireDateTime", originationExpireDateTime)
            appendSingle("usageExpireDateTime", usageExpireDateTime)
            appendSingle("usageCountLimit", usageCountLimit)
            appendSingle("userSecureId", userSecureId)

            appendBool("noAuthRequired", noAuthRequired != null)

            appendSingle("userAuthType", userAuthType)
            appendSingle("authTimeout", authTimeout)

            appendBool("allowWhileOnBody", allowWhileOnBody != null)
            appendBool("trustedUserPresenceRequired", trustedUserPresenceRequired != null)
            appendBool("trustedConfirmationRequired", trustedConfirmationRequired != null)
            appendBool("unlockedDeviceRequired", unlockedDeviceRequired != null)
            appendBool("allApplications", allApplications != null)

            appendSingle("creationDateTime", creationDateTime)
            appendSingle("origin", origin)

            appendSingle("rollbackResistant", rollbackResistant)
            appendSingle("rootOfTrust", rootOfTrust)
            appendSingle("osVersion", osVersion)
            appendSingle("osPatchLevel", osPatchLevel)
            appendSingle("attestationApplicationId", attestationApplicationId)

            appendSingle("attestationIdBrand", attestationIdBrand)
            appendSingle("attestationIdDevice", attestationIdDevice)
            appendSingle("attestationIdProduct", attestationIdProduct)
            appendSingle("attestationIdSerial", attestationIdSerial)
            appendSingle("attestationIdImei", attestationIdImei)
            appendSingle("attestationIdMeid", attestationIdMeid)
            appendSingle("attestationIdManufacturer", attestationIdManufacturer)
            appendSingle("attestationIdModel", attestationIdModel)

            appendSingle("vendorPatchLevel", vendorPatchLevel)
            appendSingle("bootPatchLevel", bootPatchLevel)

            appendBool("deviceUniqueAttestation", deviceUniqueAttestation != null)

            appendSingle("attestationIdSecondImei", attestationIdSecondImei)
            appendSingle("moduleHash", moduleHash)

            append(indent).append(")")
        }
    }

    /**
     * Helper interface for “integer-backed” authorization list values.
     *
     * Implementations encode to an ASN.1 INTEGER primitive and are also [Tagged.WithTag] so they can be wrapped into the
     * correct explicit tag during encoding of [AuthorizationList].
     */
    interface IntEncodable : Asn1Encodable<Asn1Primitive>, Tagged.WithTag<Asn1Primitive> {
        val intValue: Asn1Integer

        override fun encodeToTlv() = intValue.encodeToTlv()
    }

    /**
     * Base type for explicit tag constants used by the [AuthorizationList] schema.
     *
     * The nested [WithTag] marker binds a concrete value to a [Tagged] tag constant so generic encoding can wrap the
     * value using the correct explicit tag.
     */
    sealed class Tagged(val explicitTag: ULong) {
        /**
         * Marker interface for ASN.1-encodable values that are associated with a [Tagged] explicit tag.
         */
        sealed interface WithTag<A : Asn1Element> : Asn1Encodable<A> {
            val tagged: Tagged
        }
    }

    /**
     * Key purposes as defined by KeyMint.
     *
     * Source: https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/KeyPurpose.aidl
     */
    enum class KeyPurpose(override val intValue: Asn1Integer) : IntEncodable {
        ENCRYPT(Asn1Integer(0)),
        DECRYPT(Asn1Integer(1)),
        SIGN(Asn1Integer(2)),
        VERIFY(Asn1Integer(3)),
        DERIVE_KEY(Asn1Integer(4)), // according to aidl specification: "4 is reserved", note: not in reference implementation // TODO
        WRAP_KEY(Asn1Integer(5)),
        AGREE_KEY(Asn1Integer(6)),
        ATTEST_KEY(Asn1Integer(7));
        // From: https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/KeyPurpose.aidl

        companion object Tag : Tagged(1uL), Asn1Decodable<Asn1Primitive, KeyPurpose> {
            fun valueOf(int: Asn1Integer) = entries.first { it.intValue == int }
            override fun doDecode(src: Asn1Primitive) = valueOf(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
    }

    /**
     * Key algorithm as defined by KeyMint.
     *
     * Source: https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/Algorithm.aidl
     */
    enum class Algorithm(override val intValue: Asn1Integer) : IntEncodable {
        RSA(Asn1Integer(1)),

        //@HazardousMaterials("according to aidl specification: removed, do not reuse.") DSA(Asn1Integer(2)), // TODO: comment in for BasicParsingTests to fail
        EC(Asn1Integer(3)),
        AES(Asn1Integer(32)),
        TRIPLE_DES(Asn1Integer(33)),
        HMAC(Asn1Integer(128));
        // From: https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/Algorithm.aidl

        companion object Tag : Tagged(2uL), Asn1Decodable<Asn1Primitive, Algorithm> {
            fun valueOf(int: Asn1Integer) = entries.first { it.intValue == int }
            override fun doDecode(src: Asn1Primitive) = valueOf(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
    }

    /**
     * Key size (in bits).
     */
    class KeySize private constructor(override val intValue: Asn1Integer) : IntEncodable {
        constructor(keyLength: BitLength) : this(Asn1Integer(keyLength.bits))

        companion object Tag : Tagged(3uL), Asn1Decodable<Asn1Primitive, KeySize> {
            override fun doDecode(src: Asn1Primitive) = KeySize(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
        override fun toString(): String {
            return "KeySize(intValue=$intValue)"
        }
    }

    /**
     * Block modes as defined by KeyMint.
     *
     * Source: https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/BlockMode.aidl
     */
    enum class BlockMode(override val intValue: Asn1Integer) : IntEncodable {
        ECB(Asn1Integer(1)),
        CBC(Asn1Integer(2)),
        CTR(Asn1Integer(3)),
        GCM(Asn1Integer(32));
        // From: https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/BlockMode.aidl

        companion object Tag : Tagged(4uL), Asn1Decodable<Asn1Primitive, BlockMode> {
            fun valueOf(int: Asn1Integer) = entries.first { it.intValue == int }
            override fun doDecode(src: Asn1Primitive) = valueOf(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
    }

    /**
     * Digest modes as defined by KeyMint.
     *
     * Source: https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/Digest.aidl
     */
    enum class Digest(override val intValue: Asn1Integer) : IntEncodable {
        NONE(Asn1Integer(0)),
        MD5(Asn1Integer(1)),
        SHA1(Asn1Integer(2)),
        SHA_2_224(Asn1Integer(3)),
        SHA_2_256(Asn1Integer(4)),
        SHA_2_384(Asn1Integer(5)),
        SHA_2_512(Asn1Integer(6));
        // From: https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/Digest.aidl

        companion object Tag : Tagged(5uL), Asn1Decodable<Asn1Primitive, Digest> {
            fun valueOf(int: Asn1Integer) = entries.first { it.intValue == int }
            override fun doDecode(src: Asn1Primitive) = valueOf(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
    }

    /**
     * Padding modes as defined by KeyMint.
     *
     * Source: https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/PaddingMode.aidl
     *
     * Note: some Android sources disagree for certain values (example: PKCS7).
     */
    enum class Padding(override val intValue: Asn1Integer) : IntEncodable {
        NONE(Asn1Integer(1)),
        RSA_OAEP(Asn1Integer(2)),
        RSA_PSS(Asn1Integer(3)),
        RSA_PKCS1_1_5_ENCRYPT(Asn1Integer(4)),
        RSA_PKCS1_1_5_SIGN(Asn1Integer(5)),
        PKCS7(Asn1Integer(64));
        // From: https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/PaddingMode.aidl

        companion object Tag : Tagged(6uL), Asn1Decodable<Asn1Primitive, Padding> {
            fun valueOf(int: Asn1Integer) = entries.first { it.intValue == int }
            override fun doDecode(src: Asn1Primitive) = valueOf(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
    }

    /**
     * Indicates "caller nonce".
     *
     * Schema representation: presence/absence of a NULL value wrapped by this explicit tag.
     */
    object CallerNonce : Tagged(7uL), Asn1Encodable<Asn1Primitive> {
        override fun encodeToTlv() = Asn1.Null()
    }

    /**
     * Minimum MAC length (in bits).
     */
    class MinMacLength private constructor(override val intValue: Asn1Integer) : IntEncodable {
        constructor(macLength: BitLength) : this(Asn1Integer(macLength.bits))

        companion object Tag : Tagged(8uL), Asn1Decodable<Asn1Primitive, MinMacLength> {
            override fun doDecode(src: Asn1Primitive) = MinMacLength(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
        override fun toString(): String = "MinMacLength(intValue=$intValue)"
    }


    /**
     * Elliptic curve identifiers as defined by KeyMint.
     *
     * Source: https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/EcCurve.aidl
     */
    enum class ECCurve(override val intValue: Asn1Integer) : IntEncodable {
        P_224(Asn1Integer(0)),
        P_256(Asn1Integer(1)),
        P_384(Asn1Integer(2)),
        P_521(Asn1Integer(3)),
        CURVE_25519(Asn1Integer(4));
        // From: https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/EcCurve.aidl

        companion object Tag : Tagged(10uL), Asn1Decodable<Asn1Primitive, ECCurve> {
            fun valueOf(int: Asn1Integer) = entries.first { it.intValue == int }
            override fun doDecode(src: Asn1Primitive) = valueOf(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
    }

    /**
     * RSA public exponent.
     */
    class RsaPublicExponent private constructor(override val intValue: Asn1Integer) : IntEncodable {
        constructor(exponent: Asn1Integer.Positive) : this(intValue = exponent)

        companion object Tag : Tagged(200uL), Asn1Decodable<Asn1Primitive, RsaPublicExponent> {
            override fun doDecode(src: Asn1Primitive) = RsaPublicExponent(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
        override fun toString(): String {
            return "RsaPublicExponent($intValue)"
        }

    }

    /**
     * MGF digest.
     *
     * Corresponds to the `Tag::RSA_OAEP_MGF_DIGEST` authorization tag (tag ID `203`).
     *
     * Present in key attestation versions `100`, `200`, `300`, `400` (KeyMint only).
     * The tag number is stored in [Tag.explicitTag].
     */
    class MgfDigest(override val intValue: Asn1Integer) : IntEncodable {
        companion object Tag : Tagged(203uL), Asn1Decodable<Asn1Primitive, MgfDigest> {
            override fun doDecode(src: Asn1Primitive) = MgfDigest(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
    }

    /**
     * Indicates “rollback resistance”.
     *
     * Schema representation: presence/absence of a NULL value wrapped by this explicit tag.
     */
    object RollbackResistance : Tagged(303uL), Asn1Encodable<Asn1Primitive> {
        override fun encodeToTlv() = Asn1.Null()
    }

    /**
     * Indicates “early boot only”.
     *
     * Schema representation: presence/absence of a NULL value wrapped by this explicit tag.
     */
    object EarlyBootOnly : Tagged(305uL), Asn1Encodable<Asn1Primitive> {
        override fun encodeToTlv() = Asn1.Null()
    }

    /**
     * “Active date time” (notBefore) timestamp in milliseconds since epoch.
     */
    class ActiveDateTime private constructor(override val intValue: Asn1Integer) : IntEncodable {
        constructor(notBefore: Instant) : this(Asn1Integer(notBefore.toEpochMilliseconds()))

        companion object Tag : Tagged(400uL), Asn1Decodable<Asn1Primitive, ActiveDateTime> {
            override fun doDecode(src: Asn1Primitive) = ActiveDateTime(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
    }

    /**
     * “Origination expire date time” (notAfter) timestamp in milliseconds since epoch.
     */
    class OriginationExpireDateTime private constructor(override val intValue: Asn1Integer) :
        IntEncodable {
        constructor(notAfter: Instant) : this(Asn1Integer(notAfter.toEpochMilliseconds()))

        companion object Tag : Tagged(401uL),
            Asn1Decodable<Asn1Primitive, OriginationExpireDateTime> {
            override fun doDecode(src: Asn1Primitive) =
                OriginationExpireDateTime(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
    }

    /**
     * “Usage expire date time” timestamp in milliseconds since epoch.
     */
    class UsageExpireDateTime private constructor(override val intValue: Asn1Integer) :
        IntEncodable {
        constructor(notAfter: Instant) : this(Asn1Integer(notAfter.toEpochMilliseconds()))

        companion object Tag : Tagged(402uL), Asn1Decodable<Asn1Primitive, UsageCountLimit> {
            override fun doDecode(src: Asn1Primitive) = UsageCountLimit(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
    }

    /**
     * Limits the number of permitted uses of a key.
     */
    class UsageCountLimit(override val intValue: Asn1Integer) : IntEncodable {
        companion object Tag : Tagged(405uL), Asn1Decodable<Asn1Primitive, UsageCountLimit> {
            override fun doDecode(src: Asn1Primitive) = UsageCountLimit(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
    }

    /**
     * Secure user ID (SID).
     *
     * This value identifies the Gatekeeper / biometric enrollment set that can authorize this key.
     */
    class UserSecureId private constructor(override val intValue: Asn1Integer) : IntEncodable {
        constructor(id: Long) : this(Asn1Integer(id)) {
            require(id >= 0) { "UserSecureId must be non-negative" }
        }

        companion object Tag : Tagged(502uL), Asn1Decodable<Asn1Primitive, UserSecureId> {
            override fun doDecode(src: Asn1Primitive) = UserSecureId(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
        override fun toString(): String = "UserSecureId(intValue=$intValue)"
    }

    /**
     * Indicates that no user authentication is required.
     *
     * Schema representation: presence/absence of a NULL value wrapped by this explicit tag.
     */
    object NoAuthRequired : Tagged(503uL), Asn1Encodable<Asn1Primitive> {
        override fun encodeToTlv() = Asn1.Null()
    }


    /**
     * As per the [KeyMaster AIDL](https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/keymaster/aidl/android/hardware/keymaster/HardwareAuthenticatorType.aidl)
     * * `NONE` is modelled as empty set.
     * * `ANY` has a distinct representation as a set containing only the [Type.ANY] element
     *
     * If you want to set multiple flags, just `or` them togehter. It will produce the expected intValue: `UserAuth(Type.PASSWORD or Type.FINGERPRINT)`
     *
     */
    data class UserAuth(override val intValue: Asn1Integer) : IntEncodable {
        /**
         * Creates a [UserAuth] instance from a single [Type] value.
         */
        constructor(type: Type) : this(type.intValue)

        val authTypes: Set<Type> = when (intValue) {
            Type.ANY.intValue -> setOf(Type.ANY)
            Asn1Integer.ZERO -> emptySet()
            else -> {
                val raw = intValue.toBigInteger().longValue(exactRequired = false)
                val collected = mutableSetOf<Type>()
                if (raw and 1L > 0L) collected += Type.PASSWORD
                if (raw and 2L > 0L) collected += Type.FINGERPRINT
                collected
            }
        }

        companion object Tag : Tagged(504uL), Asn1Decodable<Asn1Primitive, UserAuth> {
            override fun doDecode(src: Asn1Primitive) = UserAuth(src.decodeToAsn1Integer())

            val NONE = UserAuth(Asn1Integer(0))
            val ANY = UserAuth(Asn1Integer(UInt.MAX_VALUE))
        }

        /**
         * Decomposed hardware authenticator type flags.
         *
         * Source:
         * https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/keymaster/aidl/android/hardware/keymaster/HardwareAuthenticatorType.aidl
         */
        enum class Type(val intValue: Asn1Integer) {
            ANY(Asn1Integer(UInt.MAX_VALUE)),
            PASSWORD(Asn1Integer(1u)),
            FINGERPRINT(Asn1Integer(2u));
        }

        override val tagged get() = Tag
        override fun toString(): String {
            return "UserAuth(" +
                    "authTypes=$authTypes, " +
                    "intValue=$intValue" +
                    ")"
        }


    }

    /**
     * Authentication timeout.
     */
    class AuthTimeout private constructor(override val intValue: Asn1Integer) : IntEncodable {
        constructor(duration: Duration) : this(Asn1Integer(duration.inWholeSeconds))

        val duration: Duration =
            Long.decodeFromAsn1ContentBytes(intValue.encodeToAsn1ContentBytes()).seconds

        init {
            require(intValue.magnitude.size <= 4) // TODO: where is this specified?
        }

        companion object Tag : Tagged(505uL), Asn1Decodable<Asn1Primitive, AuthTimeout> {
            override fun doDecode(src: Asn1Primitive) = AuthTimeout(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
        override fun toString(): String {
            return "AuthTimeout(intValue=$intValue, duration=$duration)"
        }
    }

    /**
     * Indicates “allow while on body”.
     *
     * Schema representation: presence/absence of a NULL value wrapped by this explicit tag.
     */
    object AllowWhileOnBody : Tagged(506uL), Asn1Encodable<Asn1Primitive> {
        override fun encodeToTlv() = Asn1.Null()
    }

    /**
     * Indicates “trusted user presence required”.
     *
     * Schema representation: presence/absence of a NULL value wrapped by this explicit tag.
     */
    object TrustedUserPresenceRequired : Tagged(507uL), Asn1Encodable<Asn1Primitive> {
        override fun encodeToTlv() = Asn1.Null()
    }

    /**
     * Indicates “trusted confirmation required”.
     *
     * Schema representation: presence/absence of a NULL value wrapped by this explicit tag.
     */
    object TrustedConfirmationRequired : Tagged(508uL), Asn1Encodable<Asn1Primitive> {
        override fun encodeToTlv() = Asn1.Null()
    }

    /**
     * Indicates “unlocked device required”.
     *
     * Schema representation: presence/absence of a NULL value wrapped by this explicit tag.
     */
    object UnlockedDeviceRequired : Tagged(509uL), Asn1Encodable<Asn1Primitive> {
        override fun encodeToTlv() = Asn1.Null()
    }

    /**
     * Indicates “all applications”.
     *
     * Schema representation: presence/absence of a NULL value wrapped by this explicit tag.
     */
    object AllApplications : Tagged(600uL), Asn1Encodable<Asn1Primitive> {
        override fun encodeToTlv() = Asn1.Null()
    }

    /**
     * Key creation timestamp in milliseconds since epoch.
     */
    class CreationDateTime private constructor(override val intValue: Asn1Integer) : IntEncodable {
        constructor(timestamp: Instant) : this(Asn1Integer(timestamp.toEpochMilliseconds()))

        val timestamp: Instant =
            Instant.fromEpochMilliseconds(Long.decodeFromAsn1ContentBytes(intValue.encodeToAsn1ContentBytes()))

        companion object Tag : Tagged(701uL), Asn1Decodable<Asn1Primitive, CreationDateTime> {
            override fun doDecode(src: Asn1Primitive) = CreationDateTime(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
        override fun toString(): String {
            return "CreationDateTime(intValue=$intValue, timestamp=$timestamp)"
        }
    }

    /**
     * Key origin as defined by KeyMint.
     *
     * Source: https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/KeyOrigin.aidl
     */
    enum class Origin(override val intValue: Asn1Integer) : IntEncodable {
        GENERATED(Asn1Integer(0)),
        DERIVED(Asn1Integer(1)),
        IMPORTED(Asn1Integer(2)),
        RESERVED(Asn1Integer(3)),
        SECURELY_IMPORTED(Asn1Integer(4));
        // From: https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/KeyOrigin.aidl

        companion object Tag : Tagged(702uL), Asn1Decodable<Asn1Primitive, Origin> {
            fun valueOf(int: Asn1Integer) = entries.first { it.intValue == int }
            override fun doDecode(src: Asn1Primitive) = valueOf(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
    }

    /**
     * Legacy rollback-resistant indicator (older attestation versions use this tag name/spelling).
     *
     * Schema representation: presence/absence of a NULL value wrapped by this explicit tag.
     */
    object RollbackResistent : Tagged(703uL), Asn1Encodable<Asn1Primitive> {
        override fun encodeToTlv() = Asn1.Null()
    }

    /**
     * Root of trust structure.
     *
     * This structure is known to appear in non-DER encodings (e.g., the boolean may not be encoded canonically), so the
     * implementation preserves the original boolean content for round-trip encoding.
     */
    class RootOfTrust private constructor(
        val verifiedBootKeyDigest: ByteArray,
        val deviceLocked: Boolean,
        val verifiedBootState: VerifiedBootState,
        val verifiedBootHash: ByteArray?,
        val actualBooleanValue: ByteArray
    ) : Asn1Encodable<Asn1Sequence>, Tagged.WithTag<Asn1Sequence>, PrettyPrintable {

        constructor(
            verifiedBootKeyDigest: ByteArray,
            deviceLocked: Boolean,
            verifiedBootState: VerifiedBootState,
            verifiedBootHash: ByteArray?
        ) : this(
            verifiedBootKeyDigest = verifiedBootKeyDigest,
            deviceLocked = deviceLocked,
            verifiedBootState = verifiedBootState,
            verifiedBootHash = verifiedBootHash,
            actualBooleanValue = Asn1.Bool(deviceLocked).content
        )

        companion object Tag : Tagged(704uL), Asn1Decodable<Asn1Sequence, RootOfTrust> {
            override fun doDecode(src: Asn1Sequence) = src.iterator().run {
                //NON-DER encoding. Why are the biggest players most incompetent?
                val verifiedBootKeyDigest = next().asPrimitive().content
                val (deviceLocked, actualBooleanValue) = next().asPrimitive().decode(Asn1Element.Tag.BOOL) {
                    //This isn't even DER-compliant!
                    (it.firstOrNull { it != 0.toByte() } != null) to it
                }
                val verifiedBootState = VerifiedBootState.decodeFromTlv(next().asPrimitive())
                val verifiedBootHash = if (hasNext()) next().asPrimitive().content else null

                RootOfTrust(
                    verifiedBootKeyDigest,
                    deviceLocked,
                    verifiedBootState,
                    verifiedBootHash,
                    actualBooleanValue
                )
            }
        }

        override val tagged get() = Tag

        override fun encodeToTlv() = Asn1.Sequence {
            +Asn1.OctetString(verifiedBootKeyDigest)
            +Asn1Primitive(Asn1Element.Tag.BOOL, actualBooleanValue)
            +verifiedBootState
            verifiedBootHash?.let { +Asn1.OctetString(it) }
        }

        @OptIn(ExperimentalStdlibApi::class)
        override fun toString(): String {
            return "RootOfTrust(verifiedBootKeyDigest=${verifiedBootKeyDigest.toHexString()}, deviceLocked=$deviceLocked, verifiedBootState=$verifiedBootState, verifiedBootHash=${verifiedBootHash?.toHexString()})"
        }

        @OptIn(ExperimentalStdlibApi::class)
        override fun doPrettyPrint(indent: String): String = buildString {
            val i = indent + "  "
            append(indent).append("RootOfTrust(\n")
            append(i).append("verifiedBootKeyDigest=").append(verifiedBootKeyDigest.toHexString()).append('\n')
            append(i).append("deviceLocked=").append(deviceLocked).append('\n')
            append(i).append("verifiedBootState=").append(verifiedBootState).append('\n')
            append(i).append("verifiedBootHash=").append(verifiedBootHash?.toHexString()).append('\n')
            append(indent).append(")")
        }


        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is RootOfTrust) return false

            if (deviceLocked != other.deviceLocked) return false
            if (!verifiedBootKeyDigest.contentEquals(other.verifiedBootKeyDigest)) return false
            if (verifiedBootState != other.verifiedBootState) return false
            if (!verifiedBootHash.contentEquals(other.verifiedBootHash)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = deviceLocked.hashCode()
            result = 31 * result + verifiedBootKeyDigest.contentHashCode()
            result = 31 * result + verifiedBootState.hashCode()
            result = 31 * result + verifiedBootHash.contentHashCode()
            return result
        }

        /**
         * Verified Boot state as defined by the attestation schema.
         *
         * Source: https://source.android.com/docs/security/features/keystore/attestation#schema
         */
        enum class VerifiedBootState(val intValue: UInt) : Asn1Encodable<Asn1Primitive> {
            Verified(0u),
            SelfSigned(1u),
            Unverified(2u),
            Failed(3u);
            // From: https://source.android.com/docs/security/features/keystore/attestation#schema

            override fun encodeToTlv() =
                Asn1Primitive(BERTags.ENUMERATED, intValue.encodeToAsn1ContentBytes())

            companion object : Asn1Decodable<Asn1Primitive, VerifiedBootState> {
                fun valueOf(int: UInt) = entries.first { it.intValue == int }
                override fun doDecode(src: Asn1Primitive) = src.decodeToEnum<VerifiedBootState>()
            }
        }
    }

    /**
     * OS version, encoded as an integer `MMmmss` (major/minor/sub) as per the schema.
     */
    class OsVersion(
        val major: UByte,
        val minor: UByte,
        val sub: UByte
    ) : IntEncodable {
        override val intValue =
            Asn1Integer(sub.toUInt() + minor.toUInt() * 100u + major.toUInt() * 10000u)

        companion object Tag : Tagged(705uL), Asn1Decodable<Asn1Primitive, OsVersion> {
            override fun doDecode(src: Asn1Primitive): OsVersion {
                val raw = Long.decodeFromAsn1ContentBytes(
                    src.decodeToAsn1Integer().encodeToAsn1ContentBytes()
                )
                val sub = raw % 100
                val minor = (raw % 10000) / 100
                val major = raw / 10000
                return OsVersion(major.toUByte(), minor.toUByte(), sub.toUByte())
            }
        }

        override val tagged get() = Tag
        override fun toString(): String {
            return "OsVersion(major=$major, minor=$minor, sub=$sub, intValue=$intValue)"
        }
    }

    /**
     * OS patch level as [year] and [month], encoded as `year * 100 + month` as per the schema.
     */
    class OsPatchLevel(
        val year: UShort,
        val month: Month
    ) : IntEncodable {

        override val intValue = Asn1Integer(month.number.toUInt() + year.toUInt() * 100u)

        companion object Tag : Tagged(706uL), Asn1Decodable<Asn1Primitive, OsPatchLevel> {
            override fun doDecode(src: Asn1Primitive): OsPatchLevel {
                val raw = Long.decodeFromAsn1ContentBytes(
                    src.decodeToAsn1Integer().encodeToAsn1ContentBytes()
                )
                val year = raw / 100
                val month = Month((raw % 100).toInt())
                return OsPatchLevel(year.toUShort(), month)
            }
        }

        override val tagged get() = Tag
        override fun toString(): String {
            return "OsPatchLevel(year=$year, month=$month, intValue=$intValue)"
        }
    }

    /**
     * Attestation application identifier structure.
     *
     * Schema:
     * https://source.android.com/docs/security/features/keystore/attestation#attestationapplicationid-schema
     *
     * This contains two independent ASN.1 SETs:
     * - [packageInfos] (set of [AttestationPackageInfo])
     * - [signatureDigests] (set of certificate digests)
     *
     * The schema does not define a correspondence between entries of these sets.
     *
     * #### Ordering
     * When decoded, both sets are stored using an internal order-preserving [Set] implementation so iteration preserves
     * the original element order (even if the source violates DER sorting). When encoding, such order-preserving sets
     * are emitted without re-sorting.
     */
    class AttestationApplicationId(
        val packageInfos: Set<AttestationPackageInfo>,
        val signatureDigests: Set<ByteArray>
    ) : Asn1Encodable<Asn1Element>, Tagged.WithTag<Asn1Element>, PrettyPrintable {
        companion object Tag : Tagged(709uL), Asn1Decodable<Asn1Element, AttestationApplicationId> {
            override fun doDecode(src: Asn1Element): AttestationApplicationId {
                val children = src.asEncapsulatingOctetString().children
                require(children.size == 1) // TODO: check others TLV entries so that at most 1 is given
                val sequence = children.first().asSequence()

                return sequence.iterator().run {
                    val decodedPackageInfos =
                        next().asSet().children.fold(LinkedHashSet<AttestationPackageInfo>()) { acc, el ->
                            acc += AttestationPackageInfo.decodeFromTlv(el.asSequence())
                            acc
                        }
                    val decodedSignatureDigests = next().asSet().children.fold(LinkedHashSet<ByteArray>()) { acc, el ->
                        acc += el.asOctetString().content
                        acc
                    }
                    AttestationApplicationId(
                        OrderPreservingSet(decodedPackageInfos),
                        OrderPreservingSet(decodedSignatureDigests)
                    )
                }
            }
        }

        override val tagged get() = Tag

        override fun encodeToTlv(): Asn1Element = Asn1.OctetStringEncapsulating {
            +Asn1.Sequence {
                if (packageInfos is OrderPreservingSet<*>) {
                    +Asn1Set.fromPresorted(packageInfos.map { it.encodeToTlv() })
                } else {
                    +Asn1.SetOf { packageInfos.forEach { +it } }
                }

                if (signatureDigests is OrderPreservingSet<*>) {
                    +Asn1Set.fromPresorted(signatureDigests.map { it.encodeToAsn1OctetStringPrimitive() })
                } else {
                    +Asn1.SetOf { signatureDigests.forEach { +Asn1.OctetString(it) } }
                }
            }
        }

        @OptIn(ExperimentalStdlibApi::class)
        override fun toString(): String {
            return "AttestationApplicationId(packageInfos=${packageInfos}, signatureDigests=${signatureDigests.map { it.toHexString() }})"
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as AttestationApplicationId

            if (packageInfos != other.packageInfos) return false
            if (signatureDigests != other.signatureDigests) return false

            return true
        }

        override fun hashCode(): Int {
            var result = packageInfos.hashCode()
            result = 31 * result + signatureDigests.hashCode()
            return result
        }

        // AuthorizationList.AttestationApplicationId.prettyPrint
        @OptIn(ExperimentalStdlibApi::class)
        override fun doPrettyPrint(indent: String): String = buildString {
            val i = indent + "  "
            append(indent).append("AttestationApplicationId(\n")

            append(i).append("packageInfos = [\n")
            packageInfos.forEach { pi ->
                append(i).append("  ").append(pi).append('\n')
            }
            append(i).append("]\n")

            append(i).append("signatureDigests = [\n")
            signatureDigests.forEach { d ->
                append(i).append("  ").append(d.toHexString()).append('\n')
            }
            append(i).append("]\n")

            append(indent).append(")")
        }


        /**
         * Verified Boot state enum (schema-defined).
         *
         * Note: This duplicates [RootOfTrust.VerifiedBootState] and is kept for historical/compatibility reasons.
         */
        enum class VerifiedBootState(val intValue: UInt) : Asn1Encodable<Asn1Primitive> {
            Verified(0u),
            SelfSigned(1u),
            Unverified(2u),
            Failed(3u);
            // From: https://source.android.com/docs/security/features/keystore/attestation#schema

            override fun encodeToTlv() =
                Asn1Primitive(BERTags.ENUMERATED, intValue.encodeToAsn1ContentBytes())

            companion object : Asn1Decodable<Asn1Primitive, VerifiedBootState> {
                fun valueOf(int: UInt) = entries.first { it.intValue == int }
                override fun doDecode(src: Asn1Primitive) = src.decodeToEnum<VerifiedBootState>()
            }
        }
    }

    /**
     * Package info entry within [AttestationApplicationId.packageInfos].
     */
    data class AttestationPackageInfo(
        val packageName: String,
        val version: UInt
    ) : Asn1Encodable<Asn1Sequence> {
        companion object :
            Asn1Decodable<Asn1Sequence, AttestationPackageInfo> {
            override fun doDecode(src: Asn1Sequence) = src.iterator().run {
                AttestationPackageInfo(
                    next().asOctetString().content.decodeToString(),
                    next().asPrimitive().decodeToUInt()
                )
            }
        }

        override fun encodeToTlv() = Asn1.Sequence {
            +Asn1.OctetString(packageName.encodeToByteArray())
            +Asn1.Int(version)
        }

        override fun toString(): String {
            return "AttestationPackageInfo(packageName='$packageName', version=$version)"
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is AttestationPackageInfo) return false

            if (packageName != other.packageName) return false
            if (version != other.version) return false

            return true
        }

        override fun hashCode(): Int {
            var result = packageName.hashCode()
            result = 31 * result + version.hashCode()
            return result
        }
    }

    /**
     * Attestation ID value family (device identifiers).
     *
     * All subclasses are encoded as an ASN.1 OCTET STRING wrapped by a schema-defined explicit tag.
     */
    sealed class AttestationId(val stringValue: String) : Asn1Encodable<Asn1Primitive>,
        Tagged.WithTag<Asn1Primitive> {
        override fun encodeToTlv() = Asn1.OctetString(stringValue.encodeToByteArray())
        override fun toString(): String {
            return "AttestationId(stringValue='$stringValue')"
        }

        /** Device brand. */
        class Brand(name: String) : AttestationId(name) {
            companion object Tag : Tagged(710uL)

            override val tagged get() = Tag
        }

        /** Device name / codename. */
        class Device(name: String) : AttestationId(name) {
            companion object Tag : Tagged(711uL), Asn1Decodable<Asn1Primitive, Device> {
                override fun doDecode(src: Asn1Primitive) =
                    Device(src.asOctetString().content.decodeToString())
            }

            override val tagged get() = Tag
        }

        /** Product name. */
        class Product(name: String) : AttestationId(name) {
            companion object Tag : Tagged(712uL), Asn1Decodable<Asn1Primitive, Product> {
                override fun doDecode(src: Asn1Primitive) =
                    Product(src.asOctetString().content.decodeToString())
            }

            override val tagged get() = Tag
        }

        /** Device serial number. */
        class Serial(number: String) : AttestationId(number) {
            companion object Tag : Tagged(713uL), Asn1Decodable<Asn1Primitive, Serial> {
                override fun doDecode(src: Asn1Primitive) =
                    Serial(src.asOctetString().content.decodeToString())
            }

            override val tagged get() = Tag
        }

        /** IMEI. */
        class Imei(number: String) : AttestationId(number) {
            companion object Tag : Tagged(714uL), Asn1Decodable<Asn1Primitive, Imei> {
                override fun doDecode(src: Asn1Primitive) =
                    Imei(src.asOctetString().content.decodeToString())
            }

            override val tagged get() = Tag
        }

        /** MEID. */
        class Meid(number: String) : AttestationId(number) {
            companion object Tag : Tagged(715uL), Asn1Decodable<Asn1Primitive, Meid> {
                override fun doDecode(src: Asn1Primitive) =
                    Meid(src.asOctetString().content.decodeToString())
            }

            override val tagged get() = Tag
        }

        /** Manufacturer name. */
        class Manufacturer(name: String) : AttestationId(name) {
            companion object Tag : Tagged(716uL), Asn1Decodable<Asn1Primitive, Manufacturer> {
                override fun doDecode(src: Asn1Primitive) =
                    Manufacturer(src.asOctetString().content.decodeToString())
            }

            override val tagged get() = Tag
        }

        /** Model name. */
        class Model(name: String) : AttestationId(name) {
            companion object Tag : Tagged(717uL), Asn1Decodable<Asn1Primitive, Model> {
                override fun doDecode(src: Asn1Primitive) =
                    Model(src.asOctetString().content.decodeToString())
            }

            override val tagged get() = Tag
        }

        /** Secondary IMEI (dual-SIM). */
        class SecondImei(number: String) : AttestationId(number) {
            companion object Tag : Tagged(723uL), Asn1Decodable<Asn1Primitive, SecondImei> {
                override fun doDecode(src: Asn1Primitive) =
                    SecondImei(src.asOctetString().content.decodeToString())
            }

            override val tagged get() = Tag
        }
    }

    /**
     * Patch level value family.
     *
     * Encoded as either:
     * - `YYYYMM` (no day), or
     * - `YYYYMMDD` (some devices include an extra day value).
     *
     * Note: Some OEMs (and legacy parsers) are lenient about the presence/format of the day component.
     */
    sealed class PatchLevel(
        val year: UShort,
        val month: Month,
        val day: UShort? /*This is non-compliant, but many OEMs mess this up AND the legacy google parser is also lenient here*/
    ) : IntEncodable {
        override val intValue =
            if (day == null)
                Asn1Integer(month.number.toUInt() + year.toUInt() * 100u)
            else
                Asn1Integer(day.toUInt() + month.number.toUInt() * 100u + year.toUInt() * 10000u)

        companion object {
            fun Asn1Primitive.decode(): Triple<UShort, Month, UShort?> {
                val raw = Long.decodeFromAsn1ContentBytes(
                    decodeToAsn1Integer().encodeToAsn1ContentBytes()
                )
                if (raw > 999999) {
                    val day = raw % 100
                    val monthNumber = (raw % 10000) / 100
                    val year = raw / 10000
                    return Triple(
                        year.toUShort(),
                        Month(monthNumber.toInt()),
                        day.toUShort()
                    )
                } else {
                    val monthNumber = (raw % 100)
                    val year = raw / 100
                    return Triple(
                        year.toUShort(),
                        Month(monthNumber.toInt()),
                        null
                    )
                }
            }
        }

        /**
         * Vendor patch level.
         */
        class Vendor(
            year: UShort,
            month: Month,
            day: UShort?
        ) : PatchLevel(year, month, day) {
            companion object Tag : Tagged(718uL), Asn1Decodable<Asn1Primitive, Vendor> {
                override fun doDecode(src: Asn1Primitive): Vendor = src.decode().let { (y, m, d) ->
                    Vendor(y, m, d)
                }

            }

            override val tagged get() = Tag
        }

        /**
         * Boot patch level.
         */
        class Boot(
            year: UShort,
            month: Month,
            day: UShort?
        ) : PatchLevel(year, month, day) {
            companion object Tag : Tagged(719uL), Asn1Decodable<Asn1Primitive, Boot> {
                override fun doDecode(src: Asn1Primitive): Boot = src.decode().let { (y, m, d) ->
                    Boot(y, m, d)
                }
            }

            override val tagged get() = Tag
        }

        override fun toString(): String {
            return "PatchLevel(year=$year, month=$month, day=$day, intValue=$intValue)"
        }
    }

    /**
     * Can only ever be set by privileged system apps
     */
    object DeviceUniqueAttestation : Tagged(720uL), Asn1Encodable<Asn1Primitive> {
        override fun encodeToTlv() = Asn1.Null()
    }


    /**
     * #### Undocumented, ChatGPT-generated! Take with a grain of salt!
     * In the context of Android's Keymaster and Keystore systems, the `moduleHash` is a component within the attestation data structure, specifically in the `KeyDescription` sequence. It provides a cryptographic representation of the software environment associated with the key's creation and usage.
     *
     * **Computation of `moduleHash`:**
     *
     * 1. **Modules Collection:**
     *    - The system gathers a set of `Module` entries, each representing an APEX (Android Pony EXpress) module.
     *    - Each `Module` includes:
     *      - **Package Name (`packageName`):** An octet string identifying the module.
     *      - **Version (`version`):** An integer indicating the module's version at boot time.
     *
     * 2. **DER Encoding:**
     *    - The `Modules` set is encoded using Distinguished Encoding Rules (DER), a binary encoding format for data structures described by ASN.1.
     *    - DER encoding ensures a unique, unambiguous representation of the data, which is crucial for consistent hashing.
     *
     * 3. **Ordering:**
     *    - Within the DER encoding process, the `Module` entries are ordered lexicographically by their encoded value.
     *    - This deterministic ordering guarantees that the same set of modules will always produce the same encoded output, ensuring consistency in the hash computation.
     *
     * 4. **SHA-256 Hashing:**
     *    - The system computes the SHA-256 hash of the DER-encoded `Modules` set.
     *    - The resulting 256-bit hash value is the `moduleHash`.
     *
     * This `moduleHash` serves as a fingerprint of the software environment, allowing verification processes to detect any unauthorized changes to the modules. By including the `moduleHash` in the attestation data, the system provides assurance that the key is used within a trusted and unaltered software environment.
     *
     * For a detailed definition of the `Modules` and `Module` structures, as well as the computation of `moduleHash`, you can refer to the Android Open Source Project's documentation on Keymaster's attestation process.
     */
    class ModuleHash(val sha256Digest: ByteArray) : Asn1Encodable<Asn1Primitive>,
        Tagged.WithTag<Asn1Primitive> {
        override fun encodeToTlv() = Asn1.OctetString(sha256Digest)

        @OptIn(ExperimentalStdlibApi::class)
        override fun toString(): String {
            return "ModuleHash(sha256Digest=${sha256Digest.toHexString()})"
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is ModuleHash) return false

            if (!sha256Digest.contentEquals(other.sha256Digest)) return false

            return true
        }

        override fun hashCode(): Int {
            return sha256Digest.contentHashCode()
        }

        companion object Tag : Tagged(724uL), Asn1Decodable<Asn1Primitive, ModuleHash> {
            override fun doDecode(src: Asn1Primitive) = ModuleHash(src.asOctetString().content)
        }

        override val tagged get() = Tag
    }
}


//TODO these could be made more efficient, but its not worth it at the moment
infix fun Asn1Integer.or(other: AuthorizationList.UserAuth.Type) = other or this
infix fun AuthorizationList.UserAuth.Type.or(other: Type): Asn1Integer =
    (this.intValue.toBigInteger().or(other.intValue.toBigInteger())).toAsn1Integer()

infix fun AuthorizationList.UserAuth.Type.or(other: Asn1Integer) =
    intValue.toBigInteger().or(other.toBigInteger()).toAsn1Integer()
