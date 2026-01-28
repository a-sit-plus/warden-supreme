import at.asitplus.attestation.android.AttestationKeyDescription
import at.asitplus.attestation.android.AttestationValue
import at.asitplus.attestation.android.AuthorizationList
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Integer
import at.asitplus.signum.indispensable.asn1.encoding.decodeFromAsn1ContentBytes
import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1ContentBytes
import com.google.android.attestation.AuthorizationList as GoogleAuthorizationList
import com.google.android.attestation.AttestationApplicationId as GoogleAttestationApplicationId
import com.google.android.attestation.ParsedAttestationRecord
import com.google.protobuf.ByteString
import java.time.Duration
import java.time.Instant
import java.time.LocalDate
import java.time.YearMonth
import java.util.Optional
import kotlinx.datetime.number

fun assertSemanticallyEqual(fromGoogle: ParsedAttestationRecord, androidAttestationExtension: AttestationKeyDescription) {
    checkEquals("attestationVersion", fromGoogle.attestationVersion(), androidAttestationExtension.attestationVersion)
    checkEquals(
        "attestationSecurityLevel",
        fromGoogle.attestationSecurityLevel().name,
        androidAttestationExtension.attestationSecurityLevel.name
    )
    checkEquals("keymasterVersion", fromGoogle.keymasterVersion(), androidAttestationExtension.keymasterVersion)
    checkEquals(
        "keymasterSecurityLevel",
        fromGoogle.keymasterSecurityLevel().name,
        androidAttestationExtension.keymasterSecurityLevel.name
    )
    checkByteArrayEquals(
        "attestationChallenge",
        fromGoogle.attestationChallenge().toByteArray(),
        androidAttestationExtension.attestationChallenge
    )
    checkByteArrayEquals("uniqueId", fromGoogle.uniqueId().toByteArray(), androidAttestationExtension.uniqueId)

    assertAuthorizationListSemanticallyEqual(
        "softwareEnforced",
        fromGoogle.softwareEnforced(),
        androidAttestationExtension.softwareEnforced
    )
    assertAuthorizationListSemanticallyEqual(
        "teeEnforced",
        fromGoogle.teeEnforced(),
        androidAttestationExtension.hardwareEnforced
    )
}

private fun assertAuthorizationListSemanticallyEqual(
    path: String,
    google: GoogleAuthorizationList,
    ours: AuthorizationList
) {
    checkEquals("$path.purpose", google.purpose().mapTo(sortedSetOf()) { it.name }, ours.purpose.toNamesOrEmpty("$path.purpose"))
    checkOptionalEnumEquals("$path.algorithm", google.algorithm(), ours.algorithm?.successValueOrThrow("$path.algorithm")?.name)
    checkOptionalLongEquals("$path.keySize", google.keySize(), ours.keySize?.successValueOrThrow("$path.keySize")?.intValue?.toLongValue())
    checkEquals("$path.digest", google.digest().mapTo(sortedSetOf()) { it.name }, ours.digest.toNamesOrEmpty("$path.digest"))
    checkEquals("$path.padding", google.padding().mapTo(sortedSetOf()) { it.name }, ours.padding.toNamesOrEmpty("$path.padding"))
    checkOptionalEnumEquals("$path.ecCurve", google.ecCurve(), ours.ecCurve?.successValueOrThrow("$path.ecCurve")?.name)
    checkOptionalLongEquals(
        "$path.rsaPublicExponent",
        google.rsaPublicExponent(),
        ours.rsaPublicExponent?.successValueOrThrow("$path.rsaPublicExponent")?.intValue?.toLongValue()
    )

    checkEquals(
        "$path.rollbackResistance",
        google.rollbackResistance(),
        ours.rollbackResistance != null || ours.rollbackResistant != null
    )

    checkOptionalInstantEquals(
        "$path.activeDateTime",
        google.activeDateTime(),
        ours.activeDateTime?.successValueOrThrow("$path.activeDateTime")?.intValue?.toEpochMilliInstant()
    )
    checkOptionalInstantEquals(
        "$path.originationExpireDateTime",
        google.originationExpireDateTime(),
        ours.originationExpireDateTime?.successValueOrThrow("$path.originationExpireDateTime")?.intValue?.toEpochMilliInstant()
    )
    checkOptionalInstantEquals(
        "$path.usageExpireDateTime",
        google.usageExpireDateTime(),
        ours.usageExpireDateTime?.successValueOrThrow("$path.usageExpireDateTime")?.intValue?.toEpochMilliInstant()
    )

    checkEquals("$path.noAuthRequired", google.noAuthRequired(), ours.noAuthRequired != null)

    val googleUserAuthTypes = google.userAuthType().mapTo(sortedSetOf()) { it.name }
    val oursUserAuthTypes = ours.userAuthType.toUserAuthTypeNamesOrEmpty("$path.userAuthType")
    checkEquals("$path.userAuthType", googleUserAuthTypes, oursUserAuthTypes)

    checkOptionalDurationEquals(
        "$path.authTimeout",
        google.authTimeout(),
        ours.authTimeout?.successValueOrThrow("$path.authTimeout")?.duration?.inWholeSeconds?.let { Duration.ofSeconds(it) }
    )

    checkEquals("$path.allowWhileOnBody", google.allowWhileOnBody(), ours.allowWhileOnBody != null)
    checkEquals(
        "$path.trustedUserPresenceRequired",
        google.trustedUserPresenceRequired(),
        ours.trustedUserPresenceRequired != null
    )
    checkEquals(
        "$path.trustedConfirmationRequired",
        google.trustedConfirmationRequired(),
        ours.trustedConfirmationRequired != null
    )
    checkEquals("$path.unlockedDeviceRequired", google.unlockedDeviceRequired(), ours.unlockedDeviceRequired != null)

    checkOptionalInstantEquals(
        "$path.creationDateTime",
        google.creationDateTime(),
        ours.creationDateTime?.successValueOrThrow("$path.creationDateTime")?.timestamp?.toEpochMilliseconds()
            ?.let { Instant.ofEpochMilli(it) }
    )

    checkOptionalEnumEquals("$path.origin", google.origin(), ours.origin?.successValueOrThrow("$path.origin")?.name)

    assertOptionalRootOfTrustEquals("$path.rootOfTrust", google.rootOfTrust(), ours.rootOfTrust)
    checkOptionalLongEquals("$path.osVersion", google.osVersion(), ours.osVersion?.successValueOrThrow("$path.osVersion")?.toEncodedLong())
    assertOptionalYearMonthEquals("$path.osPatchLevel", google.osPatchLevel(), ours.osPatchLevel)

    assertOptionalAttestationApplicationIdEquals(
        "$path.attestationApplicationId",
        google.attestationApplicationId(),
        ours.attestationApplicationId
    )

    assertOptionalAttestationIdEquals("$path.attestationIdBrand", google.attestationIdBrand(), ours.attestationIdBrand)
    assertOptionalAttestationIdEquals("$path.attestationIdDevice", google.attestationIdDevice(), ours.attestationIdDevice)
    assertOptionalAttestationIdEquals("$path.attestationIdProduct", google.attestationIdProduct(), ours.attestationIdProduct)
    assertOptionalAttestationIdEquals("$path.attestationIdSerial", google.attestationIdSerial(), ours.attestationIdSerial)
    assertOptionalAttestationIdEquals("$path.attestationIdImei", google.attestationIdImei(), ours.attestationIdImei)
    assertOptionalAttestationIdEquals("$path.attestationIdSecondImei", google.attestationIdSecondImei(), ours.attestationIdSecondImei)
    assertOptionalAttestationIdEquals("$path.attestationIdMeid", google.attestationIdMeid(), ours.attestationIdMeid)
    assertOptionalAttestationIdEquals("$path.attestationIdManufacturer", google.attestationIdManufacturer(), ours.attestationIdManufacturer)
    assertOptionalAttestationIdEquals("$path.attestationIdModel", google.attestationIdModel(), ours.attestationIdModel)

    assertOptionalLocalDateEquals("$path.vendorPatchLevel", google.vendorPatchLevel(), ours.vendorPatchLevel)
    assertOptionalLocalDateEquals("$path.bootPatchLevel", google.bootPatchLevel(), ours.bootPatchLevel)

    checkEquals("$path.individualAttestation", google.individualAttestation(), ours.deviceUniqueAttestation != null)

    if (google.unorderedTags().isNotEmpty()) {
        throw IllegalStateException("$path.unorderedTags differs: google has ${google.unorderedTags()}, ours does not retain unknown tags")
    }
}

private fun <T : Asn1Encodable<*>> AttestationValue<T>.successValueOrThrow(path: String): T = when (this) {
    is AttestationValue.Success -> value
    is AttestationValue.Failure<*> -> throw IllegalStateException("$path differs: ours failed to parse ($this)")
}

private fun <T : Asn1Encodable<*>> Set<AttestationValue<T>>?.toNamesOrEmpty(path: String): Set<String> =
    this?.mapTo(sortedSetOf()) { it.successValueOrThrow(path).toString() } ?: emptySet()

private fun AttestationValue<AuthorizationList.UserAuthType>?.toUserAuthTypeNamesOrEmpty(path: String): Set<String> {
    val ours = this ?: return emptySet()
    val value = ours.successValueOrThrow(path)

    return when (value) {
        AuthorizationList.UserAuthType.NONE -> emptySet()
        AuthorizationList.UserAuthType.ANY -> setOf("ANY")
        else -> setOf(value.name)
    }
}

private fun AuthorizationList.OsVersion.toEncodedLong(): Long =
    (major.toLong() * 10000L) + (minor.toLong() * 100L) + sub.toLong()

private fun assertOptionalRootOfTrustEquals(
    path: String,
    google: Optional<com.google.android.attestation.RootOfTrust>,
    ours: AttestationValue<AuthorizationList.RootOfTrust>?
) {
    if (!google.isPresent) {
        if (ours != null) {
            throw IllegalStateException("$path differs: google absent, ours present ($ours)")
        }
        return
    }
    val googleValue = google.get()
    val oursValue = ours?.successValueOrThrow(path)
        ?: throw IllegalStateException("$path differs: google present, ours absent")

    checkByteArrayEquals("$path.verifiedBootKey", googleValue.verifiedBootKey().toByteArray(), oursValue.verifiedBootKeyDigest)
    checkEquals("$path.deviceLocked", googleValue.deviceLocked(), oursValue.deviceLocked)
    checkEquals("$path.verifiedBootState", googleValue.verifiedBootState().name, oursValue.verifiedBootState.name)

    val googleHash = googleValue.verifiedBootHash().map { it.toByteArray() }.orElse(null)
    if (googleHash == null) {
        if (oursValue.verifiedBootHash.isNotEmpty()) {
            throw IllegalStateException("$path.verifiedBootHash differs: google absent, ours present (${oursValue.verifiedBootHash.toHex()})")
        }
    } else {
        checkByteArrayEquals("$path.verifiedBootHash", googleHash, oursValue.verifiedBootHash)
    }
}

private fun assertOptionalYearMonthEquals(
    path: String,
    google: Optional<YearMonth>,
    ours: AttestationValue<AuthorizationList.OsPatchLevel>?
) {
    if (!google.isPresent) {
        if (ours != null) throw IllegalStateException("$path differs: google absent, ours present ($ours)")
        return
    }
    val googleValue = google.get()
    val oursValue = ours?.successValueOrThrow(path) ?: throw IllegalStateException("$path differs: google present, ours absent")
    checkEquals("$path.year", googleValue.year.toUShort(), oursValue.year)
    checkEquals("$path.month", googleValue.monthValue, oursValue.month.number)
}

private fun assertOptionalAttestationApplicationIdEquals(
    path: String,
    google: Optional<GoogleAttestationApplicationId>,
    ours: AttestationValue<AuthorizationList.AttestationApplicationId>?
) {
    if (!google.isPresent) {
        if (ours != null) throw IllegalStateException("$path differs: google absent, ours present ($ours)")
        return
    }
    val googleValue = google.get()
    val oursValue = ours?.successValueOrThrow(path) ?: throw IllegalStateException("$path differs: google present, ours absent")

    val googlePackages = googleValue.packageInfos().mapTo(sortedSetOf()) { "${it.packageName()}:${it.version()}" }
    val oursPackages = oursValue.packageInfos.mapTo(sortedSetOf()) { "${it.packageName}:${it.version}" }
    checkEquals("$path.packageInfos", googlePackages, oursPackages)

    val googleDigests = googleValue.signatureDigests().mapTo(sortedSetOf()) { it.toByteArray().toHex() }
    val oursDigests = oursValue.signatureDigests.mapTo(sortedSetOf()) { it.toHex() }
    checkEquals("$path.signatureDigests", googleDigests, oursDigests)
}

private fun assertOptionalAttestationIdEquals(
    path: String,
    google: Optional<ByteString>,
    ours: AttestationValue<AuthorizationList.AttestationId>?
) {
    if (!google.isPresent) {
        if (ours != null) throw IllegalStateException("$path differs: google absent, ours present ($ours)")
        return
    }
    val googleValue = google.get().toStringUtf8()
    val oursValue = ours?.successValueOrThrow(path)?.stringValue
        ?: throw IllegalStateException("$path differs: google present, ours absent")
    checkEquals(path, googleValue, oursValue)
}

private fun assertOptionalLocalDateEquals(
    path: String,
    google: Optional<LocalDate>,
    ours: AttestationValue<AuthorizationList.PatchLevel>?
) {
    if (!google.isPresent) {
        if (ours != null) throw IllegalStateException("$path differs: google absent, ours present ($ours)")
        return
    }
    val googleValue = google.get()
    val oursValue = ours?.successValueOrThrow(path) ?: throw IllegalStateException("$path differs: google present, ours absent")

    checkEquals("$path.year", googleValue.year.toUShort(), oursValue.year)
    checkEquals("$path.month", googleValue.monthValue, oursValue.month.number)
    checkEquals("$path.day", googleValue.dayOfMonth.toUShort(), oursValue.day)
}

private fun checkEquals(path: String, expected: Any?, actual: Any?) {
    if (expected != actual) throw IllegalStateException("$path differs: google=$expected, ours=$actual")
}

private fun checkByteArrayEquals(path: String, expected: ByteArray, actual: ByteArray) {
    if (!expected.contentEquals(actual)) {
        throw IllegalStateException("$path differs: google=${expected.toHex()}, ours=${actual.toHex()}")
    }
}

private fun checkOptionalEnumEquals(path: String, google: Optional<out Enum<*>>, oursName: String?) {
    val googleName = if (google.isPresent) google.get().name else null
    checkEquals(path, googleName, oursName)
}

private fun checkOptionalLongEquals(path: String, google: Optional<out Number>, ours: Long?) {
    val googleValue = if (google.isPresent) google.get().toLong() else null
    checkEquals(path, googleValue, ours)
}

private fun checkOptionalInstantEquals(path: String, google: Optional<Instant>, ours: Instant?) {
    val googleValue = if (google.isPresent) google.get() else null
    checkEquals(path, googleValue, ours)
}

private fun checkOptionalDurationEquals(path: String, google: Optional<Duration>, ours: Duration?) {
    val googleValue = if (google.isPresent) google.get() else null
    checkEquals(path, googleValue, ours)
}

private fun Asn1Integer.toLongValue(): Long =
    Long.decodeFromAsn1ContentBytes(encodeToAsn1ContentBytes())

private fun Asn1Integer.toEpochMilliInstant(): Instant =
    Instant.ofEpochMilli(toLongValue())

private fun ByteArray.toHex(): String = joinToString(separator = "") { b -> "%02x".format(b) }
