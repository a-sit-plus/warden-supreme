import at.asitplus.attestation.android.AttestationKeyDescription
import at.asitplus.attestation.android.AttestationValue
import at.asitplus.attestation.android.AuthorizationList
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Integer
import at.asitplus.signum.indispensable.asn1.encoding.decodeFromAsn1ContentBytes
import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1ContentBytes
import com.google.android.attestation.ParsedAttestationRecord
import com.google.protobuf.ByteString
import kotlinx.datetime.number
import java.time.Duration
import java.time.Instant
import java.time.LocalDate
import java.time.YearMonth
import java.util.*
import com.google.android.attestation.AttestationApplicationId as GoogleAttestationApplicationId
import com.google.android.attestation.AuthorizationList as GoogleAuthorizationList

fun assertSemanticallyEqual(
    fromGoogle: ParsedAttestationRecord,
    androidAttestationExtension: AttestationKeyDescription
) {
    val diffs = SemanticDiffCollector()

    diffs.capture {
        checkEquals(
            "attestationVersion",
            fromGoogle.attestationVersion(),
            androidAttestationExtension.attestationVersion
        )
    }
    diffs.capture {
        checkEnumNameEquals(
            "attestationSecurityLevel",
            fromGoogle.attestationSecurityLevel(),
            androidAttestationExtension.attestationSecurityLevel
        )
    }
    diffs.capture {
        checkEquals("keymasterVersion", fromGoogle.keymasterVersion(), androidAttestationExtension.keymasterVersion)
    }
    diffs.capture {
        checkEnumNameEquals(
            "keymasterSecurityLevel",
            fromGoogle.keymasterSecurityLevel(),
            androidAttestationExtension.keymasterSecurityLevel
        )
    }
    diffs.capture {
        checkByteArrayEquals(
            "attestationChallenge",
            fromGoogle.attestationChallenge().toByteArray(),
            androidAttestationExtension.attestationChallenge
        )
    }
    diffs.capture {
        checkByteArrayEquals("uniqueId", fromGoogle.uniqueId().toByteArray(), androidAttestationExtension.uniqueId)
    }

    diffs.capture {
        assertAuthorizationListSemanticallyEqual(
            diffs,
            "softwareEnforced",
            fromGoogle.softwareEnforced(),
            androidAttestationExtension.softwareEnforced
        )
    }
    diffs.capture {
        assertAuthorizationListSemanticallyEqual(
            diffs,
            "teeEnforced",
            fromGoogle.teeEnforced(),
            androidAttestationExtension.hardwareEnforced
        )
    }

    diffs.reportSoftDiffs()
    diffs.throwIfAny()
}

private fun assertAuthorizationListSemanticallyEqual(
    diffs: SemanticDiffCollector,
    path: String,
    google: GoogleAuthorizationList,
    ours: AuthorizationList
) {
    diffs.capture {
        checkEquals(
            "$path.purpose",
            google.purpose().mapTo(sortedSetOf()) { it.name },
            ours.purpose.toEnumNamesOrEmpty("$path.purpose").filterNot { it == "DERIVE_KEY" }.toSortedSet()
        )
    }
    diffs.capture {
        checkOptionalEnumNameEquals(
            "$path.algorithm",
            google.algorithm(),
            ours.algorithm?.successValueOrThrow("$path.algorithm")?.name
        )
    }
    diffs.capture {
        checkOptionalLongEquals(
            "$path.keySize",
            google.keySize(),
            ours.keySize?.successValueOrThrow("$path.keySize")?.intValue?.toLongValue()
        )
    }
    diffs.capture {
        checkEquals(
            "$path.digest",
            google.digest().mapTo(sortedSetOf()) { it.name },
            ours.digest.toEnumNamesOrEmpty("$path.digest")
        )
    }
    diffs.capture {
        checkEquals(
            "$path.padding",
            google.padding().mapTo(sortedSetOf()) { it.name },
            ours.padding.toEnumNamesOrEmpty("$path.padding")
        )
    }
    diffs.capture {
        checkOptionalEnumNameEquals(
            "$path.ecCurve",
            google.ecCurve(),
            ours.ecCurve?.successValueOrThrow("$path.ecCurve")?.name
        )
    }
    diffs.capture {
        checkOptionalLongEquals(
            "$path.rsaPublicExponent",
            google.rsaPublicExponent(),
            ours.rsaPublicExponent?.successValueOrThrow("$path.rsaPublicExponent")?.intValue?.toLongValue()
        )
    }

    diffs.capture {
        // Soft diff only: our model has both rollbackResistance and rollbackResistant variants depending on attestation version.
        val oursRollbackResistance = ours.rollbackResistance != null
        if (google.rollbackResistance() != oursRollbackResistance) {
            diffs.addSoftDiff("$path.rollbackResistance differs: google=${google.rollbackResistance()}, ours=$oursRollbackResistance")
        }

        if (google.unorderedTags().contains(703) && ours.rollbackResistant == null)
            diffs.addSoftDiff("$path.rollbackResistant differs: google has it, ours not")
    }

    diffs.capture {
        checkOptionalInstantEquals(
            "$path.activeDateTime",
            google.activeDateTime(),
            ours.activeDateTime?.successValueOrThrow("$path.activeDateTime")?.intValue?.toEpochMilliInstant()
        )
    }
    diffs.capture {
        checkOptionalInstantEquals(
            "$path.originationExpireDateTime",
            google.originationExpireDateTime(),
            ours.originationExpireDateTime?.successValueOrThrow("$path.originationExpireDateTime")?.intValue?.toEpochMilliInstant()
        )
    }
    diffs.capture {
        checkOptionalInstantEquals(
            "$path.usageExpireDateTime",
            google.usageExpireDateTime(),
            ours.usageExpireDateTime?.successValueOrThrow("$path.usageExpireDateTime")?.intValue?.toEpochMilliInstant()
        )
    }

    diffs.capture {
        checkEquals("$path.noAuthRequired", google.noAuthRequired(), ours.noAuthRequired != null)
    }

    diffs.capture {
        val googleUserAuth = googleUserAuthTypeToLong(google.userAuthType())
        val oursUserAuth = ours.userAuthType?.successValueOrThrow("$path.userAuthType")
        if (googleUserAuth == 0L && oursUserAuth == null) return@capture
        if (googleUserAuth == 0L && (oursUserAuth!!.authTypes.isEmpty())) return@capture
        checkEquals("$path.userAuthType", google.userAuthType().map { it.name }.toSet(), oursUserAuth?.authTypes?.map { it.name }?.toSet())
    }

    diffs.capture {
        checkOptionalDurationEquals(
            "$path.authTimeout",
            google.authTimeout(),
            ours.authTimeout?.successValueOrThrow("$path.authTimeout")?.duration?.inWholeSeconds?.let {
                Duration.ofSeconds(
                    it
                )
            }
        )
    }

    diffs.capture { checkEquals("$path.allowWhileOnBody", google.allowWhileOnBody(), ours.allowWhileOnBody != null) }
    diffs.capture {
        checkEquals(
            "$path.trustedUserPresenceRequired",
            google.trustedUserPresenceRequired(),
            ours.trustedUserPresenceRequired != null
        )
    }
    diffs.capture {
        checkEquals(
            "$path.trustedConfirmationRequired",
            google.trustedConfirmationRequired(),
            ours.trustedConfirmationRequired != null
        )
    }
    diffs.capture {
        checkEquals(
            "$path.unlockedDeviceRequired",
            google.unlockedDeviceRequired(),
            ours.unlockedDeviceRequired != null
        )
    }

    diffs.capture {
        checkOptionalInstantEquals(
            "$path.creationDateTime",
            google.creationDateTime(),
            ours.creationDateTime?.successValueOrThrow("$path.creationDateTime")?.timestamp?.toEpochMilliseconds()
                ?.let { Instant.ofEpochMilli(it) }
        )
    }

    diffs.capture {
        assertOptionalOriginEquals(diffs, "$path.origin", google.origin(), ours.origin)
    }

    diffs.capture {
        assertOptionalRootOfTrustEquals(
            diffs,
            "$path.rootOfTrust",
            google.rootOfTrust(),
            ours.rootOfTrust
        )
    }
    diffs.capture {
        checkOptionalLongEquals(
            "$path.osVersion",
            google.osVersion(),
            ours.osVersion?.successValueOrThrow("$path.osVersion")?.toEncodedLong()
        )
    }
    diffs.capture {
        assertOptionalYearMonthEquals(
            diffs,
            "$path.osPatchLevel",
            google.osPatchLevel(),
            ours.osPatchLevel
        )
    }

    diffs.capture {
        assertOptionalAttestationApplicationIdEquals(
            diffs,
            "$path.attestationApplicationId",
            google.attestationApplicationId(),
            ours.attestationApplicationId
        )
    }

    diffs.capture {
        assertOptionalAttestationIdEquals(
            diffs,
            "$path.attestationIdBrand",
            google.attestationIdBrand(),
            ours.attestationIdBrand
        )
    }
    diffs.capture {
        assertOptionalAttestationIdEquals(
            diffs,
            "$path.attestationIdDevice",
            google.attestationIdDevice(),
            ours.attestationIdDevice
        )
    }
    diffs.capture {
        assertOptionalAttestationIdEquals(
            diffs,
            "$path.attestationIdProduct",
            google.attestationIdProduct(),
            ours.attestationIdProduct
        )
    }
    diffs.capture {
        assertOptionalAttestationIdEquals(
            diffs,
            "$path.attestationIdSerial",
            google.attestationIdSerial(),
            ours.attestationIdSerial
        )
    }
    diffs.capture {
        assertOptionalAttestationIdEquals(
            diffs,
            "$path.attestationIdImei",
            google.attestationIdImei(),
            ours.attestationIdImei
        )
    }
    diffs.capture {
        assertOptionalAttestationIdEquals(
            diffs,
            "$path.attestationIdSecondImei",
            google.attestationIdSecondImei(),
            ours.attestationIdSecondImei
        )
    }
    diffs.capture {
        assertOptionalAttestationIdEquals(
            diffs,
            "$path.attestationIdMeid",
            google.attestationIdMeid(),
            ours.attestationIdMeid
        )
    }
    diffs.capture {
        assertOptionalAttestationIdEquals(
            diffs,
            "$path.attestationIdManufacturer",
            google.attestationIdManufacturer(),
            ours.attestationIdManufacturer
        )
    }
    diffs.capture {
        assertOptionalAttestationIdEquals(
            diffs,
            "$path.attestationIdModel",
            google.attestationIdModel(),
            ours.attestationIdModel
        )
    }

    diffs.capture {
        assertOptionalLocalDateEqualsBestEffortSoft(
            diffs,
            "$path.vendorPatchLevel",
            google.vendorPatchLevel(),
            ours.vendorPatchLevel
        )
    }
    diffs.capture {
        assertOptionalLocalDateEqualsBestEffortSoft(
            diffs,
            "$path.bootPatchLevel",
            google.bootPatchLevel(),
            ours.bootPatchLevel
        )
    }

    diffs.capture {
        checkEquals(
            "$path.individualAttestation",
            google.individualAttestation(),
            ours.deviceUniqueAttestation != null
        )
    }

    diffs.capture {
        if (google.unorderedTags().filterNot { it == 719 }.isNotEmpty()) {
            if (google.unorderedTags().containsAll(ours.additionalProperties.map { it.tag.tagValue.toInt() }))
                throw IllegalStateException("$path.unorderedTags differs: google has ${google.unorderedTags()}, ours: ${ours.additionalProperties}")
        }
    }
}

private fun <T : Asn1Encodable<*>> AttestationValue<T>.successValueOrThrow(path: String): T = when (this) {
    is AttestationValue.Success -> value
    is AttestationValue.Failure<*> -> throw IllegalStateException("$path differs: ours failed to parse ($this)")
}

private fun <E> Set<AttestationValue<E>>?.toEnumNamesOrEmpty(path: String): Set<String>
        where E : Asn1Encodable<*>, E : Enum<E> =
    this?.mapTo(sortedSetOf()) { it.successValueOrThrow(path).name } ?: emptySet()

private fun AuthorizationList.OsVersion.toEncodedLong(): Long =
    (major.toLong() * 10000L) + (minor.toLong() * 100L) + sub.toLong()

private fun assertOptionalRootOfTrustEquals(
    diffs: SemanticDiffCollector,
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

    diffs.capture {
        checkByteArrayEquals(
            "$path.verifiedBootKey",
            googleValue.verifiedBootKey().toByteArray(),
            oursValue.verifiedBootKeyDigest
        )
    }
    diffs.capture { checkEquals("$path.deviceLocked", googleValue.deviceLocked(), oursValue.deviceLocked) }
    diffs.capture {
        checkEnumNameEquals(
            "$path.verifiedBootState",
            googleValue.verifiedBootState(),
            oursValue.verifiedBootState
        )
    }

    val googleHash = googleValue.verifiedBootHash().map { it.toByteArray() }.orElse(null)
    if (googleHash == null || googleHash.isEmpty()) {
        diffs.capture {
            if (oursValue.verifiedBootHash != null && (oursValue.verifiedBootHash.filterNot { it == 0.toByte() }
                    .isNotEmpty())) {
                diffs.addSoftDiff("We got a verified boot hash: ${oursValue.verifiedBootHash.toHex()},  google parser did not: $googleValue")
            }
        }
    } else {
        diffs.capture {
            checkByteArrayEquals(
                "$path.verifiedBootHash",
                googleHash,
                oursValue.verifiedBootHash ?: byteArrayOf()
            )
        }
    }
}

private fun assertOptionalYearMonthEquals(
    diffs: SemanticDiffCollector,
    path: String,
    google: Optional<YearMonth>,
    ours: AttestationValue<AuthorizationList.OsPatchLevel>?
) {
    if (!google.isPresent) {
        if (ours != null) throw IllegalStateException("$path differs: google absent, ours present ($ours)")
        return
    }
    val googleValue = google.get()
    if ((googleValue == YearMonth.of(
            2048,
            1
        )) && (ours?.failureOrNull()?.rawAsn1Value?.toDerHexString() == "0203032000")
    )
        return //we patched this out
    val oursValue =
        ours?.successValueOrThrow(path) ?: throw IllegalStateException("$path differs: google present, ours absent")
    diffs.capture { checkEquals("$path.year", googleValue.year.toUShort(), oursValue.year) }
    diffs.capture { checkEquals("$path.month", googleValue.monthValue, oursValue.month.number) }
}

private fun assertOptionalAttestationApplicationIdEquals(
    diffs: SemanticDiffCollector,
    path: String,
    google: Optional<GoogleAttestationApplicationId>,
    ours: AttestationValue<AuthorizationList.AttestationApplicationId>?
) {
    if (!google.isPresent) {
        if (ours != null) throw IllegalStateException("$path differs: google absent, ours present ($ours)")
        return
    }
    val googleValue = google.get()
    val oursValue =
        ours?.successValueOrThrow(path) ?: throw IllegalStateException("$path differs: google present, ours absent")

    val googlePackages = googleValue.packageInfos().mapTo(sortedSetOf()) { "${it.packageName()}:${it.version()}" }
    val oursPackages = oursValue.packageInfos.mapTo(sortedSetOf()) { "${it.packageName}:${it.version}" }
    diffs.capture { checkEquals("$path.packageInfos", googlePackages, oursPackages) }

    val googleDigests = googleValue.signatureDigests().mapTo(sortedSetOf()) { it.toByteArray().toHex() }
    val oursDigests = oursValue.signatureDigests.mapTo(sortedSetOf()) { it.toHex() }
    diffs.capture { checkEquals("$path.signatureDigests", googleDigests, oursDigests) }
}

private fun assertOptionalAttestationIdEquals(
    diffs: SemanticDiffCollector,
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
    diffs.capture { checkEquals(path, googleValue, oursValue) }
}

private fun assertOptionalLocalDateEqualsBestEffortSoft(
    diffs: SemanticDiffCollector,
    path: String,
    google: Optional<LocalDate>,
    ours: AttestationValue<AuthorizationList.PatchLevel>?
) {
    if (!google.isPresent || google.get() == LocalDate.of(2000, 1, 1)) {
        // Treat "absent in Google" as equivalent to "failed to parse in ours".
        if (ours is AttestationValue.Success) {
            diffs.addSoftDiff("$path differs: google absent, ours present ($ours)")
        }
        return
    }
    val googleValue = google.get()
    if (ours !is AttestationValue.Success) {
        if (googleValue == LocalDate.of(
                2048,
                1,
                1
            ) /*we patched this out*/ && ours!!.failureOrNull()!!.rawAsn1Value.toDerHexString() == "020401388001"
        )
            return
        diffs.addSoftDiff("$path differs: google present ($googleValue), ours ${if (ours == null) "absent" else "failed"} ($ours)")
        return
    }
    val oursValue = ours.value

    val expectedYear = googleValue.year.toUShort()
    val expectedMonth = googleValue.monthValue
    val expectedDay = googleValue.dayOfMonth.toUShort()

    val actualYear = oursValue.year
    val actualMonth = oursValue.month.number
    val actualDay = (oursValue.day ?: 0u).toInt().let { if (it == 0) 1 else it }.toUShort()

    if (expectedYear != actualYear || expectedMonth != actualMonth || expectedDay != actualDay) {
        diffs.addSoftDiff(
            "$path differs: google=${googleValue.year}-${googleValue.monthValue}-${googleValue.dayOfMonth}, " +
                    "ours=${actualYear}-${actualMonth}-${actualDay}"
        )
    }
}

private class SemanticDiffCollector {
    private val hardDiffs = mutableListOf<Throwable>()
    private val softDiffs = mutableListOf<Throwable>()

    fun capture(block: () -> Unit) {
        try {
            block()
        } catch (t: Throwable) {
            hardDiffs += t
        }
    }

    fun addSoftDiff(message: String) {
        softDiffs += IllegalStateException(message)
    }

    fun reportSoftDiffs() {
        if (softDiffs.isEmpty()) return
        System.err.println("Semantic equality soft differences (${softDiffs.size}):")
        softDiffs.forEachIndexed { index, t ->
            //System.err.println("  ${index + 1}) ${t.message}")
            throw IllegalArgumentException(t.message)
        }
    }

    fun throwIfAny() {
        if (hardDiffs.isEmpty()) return
        val ex = IllegalStateException("Semantic equality failed with ${hardDiffs.size} difference(s)")
        hardDiffs.forEach(ex::addSuppressed)
        softDiffs.forEach(ex::addSuppressed)
        throw ex
    }
}

private fun checkEquals(path: String, expected: Any?, actual: Any?) {
    if (expected != actual) throw IllegalStateException("$path differs: google=$expected, ours=$actual")
}

private fun checkByteArrayEquals(path: String, expected: ByteArray, actual: ByteArray) {
    if (!expected.contentEquals(actual)) {
        throw IllegalStateException("$path differs: google=${expected.toHex()}, ours=${actual.toHex()}")
    }
}

private fun checkEnumNameEquals(path: String, google: Enum<*>, ours: Enum<*>) {
    val googleName = normalizeEnumName(google.name)
    val oursName = normalizeEnumName(ours.name)
    checkEquals(path, googleName, oursName)
}

private fun checkOptionalEnumNameEquals(path: String, google: Optional<out Enum<*>>, oursName: String?) {
    val googleName = if (google.isPresent) normalizeEnumName(google.get().name) else null
    val oursNorm = normalizeEnumName(oursName)
    checkEquals(path, googleName, oursNorm)
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

private fun normalizeEnumName(name: String?): String? =
    name?.replace("_", "")?.uppercase()

private fun googleUserAuthTypeToLong(types: Set<com.google.android.attestation.AuthorizationList.UserAuthType>): Long {
    if (types.contains(com.google.android.attestation.AuthorizationList.UserAuthType.USER_AUTH_TYPE_NONE)) return 0L

    var result = 0L
    types.forEach { type ->
        when (type) {
            com.google.android.attestation.AuthorizationList.UserAuthType.PASSWORD -> result = result or 1L
            com.google.android.attestation.AuthorizationList.UserAuthType.FINGERPRINT -> result = result or 2L
            com.google.android.attestation.AuthorizationList.UserAuthType.USER_AUTH_TYPE_ANY -> result =
                UInt.MAX_VALUE.toLong()

            com.google.android.attestation.AuthorizationList.UserAuthType.USER_AUTH_TYPE_NONE -> {}
        }
    }
    return result
}

private fun assertOptionalOriginEquals(
    diffs: SemanticDiffCollector,
    path: String,
    google: Optional<com.google.android.attestation.AuthorizationList.KeyOrigin>,
    ours: AttestationValue<AuthorizationList.Origin>?
) {
    if (!google.isPresent) {
        if (ours != null) {
            throw IllegalStateException("$path differs: google absent, ours present ($ours)")
        }
        return
    }

    val googleName = normalizeEnumName(google.get().name)
    val oursName = normalizeEnumName(ours?.successValueOrThrow(path)?.name)

    if (googleName == oursName) return
    val swappedOk =
        (googleName == "IMPORTED" && oursName == "DERIVED") || (googleName == "DERIVED" && oursName == "IMPORTED")
    if (swappedOk) return

    diffs.capture { checkEquals(path, googleName, oursName) }
}
