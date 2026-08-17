@file:OptIn(ExperimentalStdlibApi::class, ExperimentalTime::class)

package at.asitplus.warden.collector.shared

import at.asitplus.attestation.android.AttestationKeyDescription
import at.asitplus.attestation.android.AttestationValue
import at.asitplus.attestation.android.AuthorizationList
import at.asitplus.attestation.android.androidAttestationExtension
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.*
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * One-way, human-readable rendering of Android key-attestation contents to [JsonObject], for display
 * (e.g. the collector app's JSON tree, or a future web UI listing collected proofs). Values are
 * decoded to their intelligible form — enum names, decimal integers, ISO instants, hex digests —
 * rather than raw ASN.1. Deserialization is intentionally not supported.
 *
 * Lives in collector-shared (jvm + android + ios) so both the app and the backend can use it.
 */

/** Renders the full attestation extension of [this] leaf certificate, or null if absent/unparsable. */
fun X509Certificate.androidAttestationJson(): JsonObject? = androidAttestationExtension?.toReadableJson()

/** Renders the attestation extension closest to the root of [this] chain, or null if none present. */
fun CertificateChain.androidAttestationJson(): JsonObject? = androidAttestationExtension?.toReadableJson()

/** Renders an [AttestationKeyDescription] (both authorization lists plus the header fields). */
fun AttestationKeyDescription.toReadableJson(): JsonObject = buildJsonObject {
    put("attestationVersion", JsonPrimitive(attestationVersion))
    put("attestationSecurityLevel", JsonPrimitive(attestationSecurityLevel.name))
    put("keyMintVersion", JsonPrimitive(keyMintVersion))
    put("keyMintSecurityLevel", JsonPrimitive(keyMintSecurityLevel.name))
    put("attestationChallenge", JsonPrimitive(attestationChallenge.toHexString()))
    put("uniqueId", JsonPrimitive(uniqueId.toHexString()))
    put("softwareEnforced", softwareEnforced.toReadableJson())
    put("hardwareEnforced", hardwareEnforced.toReadableJson())
}

/** Renders a single [AuthorizationList], emitting only the tags that are actually present. */
fun AuthorizationList.toReadableJson(): JsonObject = buildJsonObject {
    purpose?.let { v -> put("purpose", v.toJsonArray { JsonPrimitive(it.name) }) }
    algorithm?.let { v -> put("algorithm", v.toJson { JsonPrimitive(it.name) }) }
    keySize?.let { v -> put("keySize", v.toJson { it.intValue.numericJson() }) }
    blockMode?.let { v -> put("blockMode", v.toJsonArray { JsonPrimitive(it.name) }) }
    digest?.let { v -> put("digest", v.toJsonArray { JsonPrimitive(it.name) }) }
    padding?.let { v -> put("padding", v.toJsonArray { JsonPrimitive(it.name) }) }
    callerNonce?.let { v -> put("callerNonce", v.toJson { JsonPrimitive(true) }) }
    minMacLength?.let { v -> put("minMacLength", v.toJson { it.intValue.numericJson() }) }
    ecCurve?.let { v -> put("ecCurve", v.toJson { JsonPrimitive(it.name) }) }
    rsaPublicExponent?.let { v -> put("rsaPublicExponent", v.toJson { it.intValue.numericJson() }) }
    mgfDigest?.let { v -> put("mgfDigest", v.toJsonArray { it.intValue.numericJson() }) }
    rollbackResistance?.let { v -> put("rollbackResistance", v.toJson { JsonPrimitive(true) }) }
    earlyBootOnly?.let { v -> put("earlyBootOnly", v.toJson { JsonPrimitive(true) }) }
    activeDateTime?.let { v -> put("activeDateTime", v.toJson { epochMillisJson(it.intValue) }) }
    originationExpireDateTime?.let { v -> put("originationExpireDateTime", v.toJson { epochMillisJson(it.intValue) }) }
    usageExpireDateTime?.let { v -> put("usageExpireDateTime", v.toJson { epochMillisJson(it.intValue) }) }
    usageCountLimit?.let { v -> put("usageCountLimit", v.toJson { it.intValue.numericJson() }) }
    userSecureId?.let { v -> put("userSecureId", v.toJson { it.intValue.numericJson() }) }
    noAuthRequired?.let { v -> put("noAuthRequired", v.toJson { JsonPrimitive(true) }) }
    userAuthType?.let { v -> put("userAuth", v.toJson { userAuthJson(it) }) }
    authTimeout?.let { v -> put("authTimeout", v.toJson { JsonPrimitive(it.duration.toString()) }) }
    allowWhileOnBody?.let { v -> put("allowWhileOnBody", v.toJson { JsonPrimitive(true) }) }
    trustedUserPresenceRequired?.let { v -> put("trustedUserPresenceRequired", v.toJson { JsonPrimitive(true) }) }
    trustedConfirmationRequired?.let { v -> put("trustedConfirmationRequired", v.toJson { JsonPrimitive(true) }) }
    unlockedDeviceRequired?.let { v -> put("unlockedDeviceRequired", v.toJson { JsonPrimitive(true) }) }
    allApplications?.let { v -> put("allApplications", v.toJson { JsonPrimitive(true) }) }
    creationDateTime?.let { v -> put("creationDateTime", v.toJson { JsonPrimitive(it.timestamp.toString()) }) }
    origin?.let { v -> put("origin", v.toJson { JsonPrimitive(it.name) }) }
    rollbackResistant?.let { v -> put("rollbackResistant", v.toJson { JsonPrimitive(true) }) }
    rootOfTrust?.let { v -> put("rootOfTrust", v.toJson { rootOfTrustJson(it) }) }
    osVersion?.let { v -> put("osVersion", v.toJson { JsonPrimitive("${it.major}.${it.minor}.${it.sub}") }) }
    osPatchLevel?.let { v -> put("osPatchLevel", v.toJson { JsonPrimitive(it.toYearMonth().toString()) }) }
    attestationApplicationId?.let { v -> put("attestationApplicationId", v.toJson { attestationAppIdJson(it) }) }
    attestationIdBrand?.let { v -> put("attestationIdBrand", v.toJson { JsonPrimitive(it.stringValue) }) }
    attestationIdDevice?.let { v -> put("attestationIdDevice", v.toJson { JsonPrimitive(it.stringValue) }) }
    attestationIdProduct?.let { v -> put("attestationIdProduct", v.toJson { JsonPrimitive(it.stringValue) }) }
    attestationIdSerial?.let { v -> put("attestationIdSerial", v.toJson { JsonPrimitive(it.stringValue) }) }
    attestationIdImei?.let { v -> put("attestationIdImei", v.toJson { JsonPrimitive(it.stringValue) }) }
    attestationIdMeid?.let { v -> put("attestationIdMeid", v.toJson { JsonPrimitive(it.stringValue) }) }
    attestationIdManufacturer?.let { v -> put("attestationIdManufacturer", v.toJson { JsonPrimitive(it.stringValue) }) }
    attestationIdModel?.let { v -> put("attestationIdModel", v.toJson { JsonPrimitive(it.stringValue) }) }
    vendorPatchLevel?.let { v -> put("vendorPatchLevel", v.toJson { JsonPrimitive(patchLevelString(it)) }) }
    bootPatchLevel?.let { v -> put("bootPatchLevel", v.toJson { JsonPrimitive(patchLevelString(it)) }) }
    deviceUniqueAttestation?.let { v -> put("deviceUniqueAttestation", v.toJson { JsonPrimitive(true) }) }
    attestationIdSecondImei?.let { v -> put("attestationIdSecondImei", v.toJson { JsonPrimitive(it.stringValue) }) }
    moduleHash?.let { v -> put("moduleHash", v.toJson { JsonPrimitive(it.sha256Digest.toHexString()) }) }
    additionalProperties.takeIf { it.isNotEmpty() }
        ?.let { extras -> put("additionalProperties", JsonArray(extras.map { JsonPrimitive(it.toDerHexString()) })) }
}

// --- helpers -----------------------------------------------------------------------------------

/** Unwraps a single [AttestationValue]: success → [success]; failure → a small {_unparsed, _rawDer} object. */
private fun <T : Asn1Encodable<*>> AttestationValue<T>.toJson(success: (T) -> JsonElement): JsonElement =
    fold(onSuccess = success, onFailure = { name, _, raw -> failureJson(name, raw) })

/** Unwraps a set of [AttestationValue]s into a JSON array. */
private fun <T : Asn1Encodable<*>> Set<AttestationValue<T>>.toJsonArray(success: (T) -> JsonElement): JsonElement =
    JsonArray(map { it.toJson(success) })

private fun failureJson(elementName: String, raw: Asn1Element): JsonElement = buildJsonObject {
    put("_unparsed", JsonPrimitive(elementName))
    put("_rawDer", JsonPrimitive(raw.toDerHexString()))
}

/** Decimal number if it fits in a Long, otherwise the value's string form. */
private fun Asn1Integer.numericJson(): JsonElement =
    runCatching { Long.decodeFromAsn1ContentBytes(encodeToAsn1ContentBytes()) }.getOrNull()
        ?.let { JsonPrimitive(it) } ?: JsonPrimitive(toString())

/** Milliseconds-since-epoch integer rendered as an ISO-8601 instant (falls back to the raw number). */
private fun epochMillisJson(millis: Asn1Integer): JsonElement =
    runCatching {
        Instant.fromEpochMilliseconds(Long.decodeFromAsn1ContentBytes(millis.encodeToAsn1ContentBytes())).toString()
    }.getOrNull()?.let { JsonPrimitive(it) } ?: millis.numericJson()

private fun userAuthJson(userAuth: AuthorizationList.UserAuth): JsonElement = buildJsonObject {
    put("authTypes", JsonArray(userAuth.authTypes.map { JsonPrimitive(it.name) }))
    put("raw", userAuth.intValue.numericJson())
}

private fun rootOfTrustJson(rot: AuthorizationList.RootOfTrust): JsonElement = buildJsonObject {
    put("deviceLocked", JsonPrimitive(rot.deviceLocked))
    put("verifiedBootState", JsonPrimitive(rot.verifiedBootState.name))
    put("verifiedBootKeyDigest", JsonPrimitive(rot.verifiedBootKeyDigest.toHexString()))
    rot.verifiedBootHash?.let { put("verifiedBootHash", JsonPrimitive(it.toHexString())) }
}

private fun attestationAppIdJson(appId: AuthorizationList.AttestationApplicationId): JsonElement = buildJsonObject {
    put("packageInfos", JsonArray(appId.packageInfos.map { info ->
        buildJsonObject {
            put("packageName", JsonPrimitive(info.packageName))
            put("version", JsonPrimitive(info.version.toLong()))
        }
    }))
    put("signatureDigests", JsonArray(appId.signatureDigests.map { JsonPrimitive(it.toHexString()) }))
}

private fun patchLevelString(patch: AuthorizationList.PatchLevel): String {
    val month = (patch.month.ordinal + 1).toString().padStart(2, '0')
    return if (patch.day == null) "${patch.year}-$month"
    else "${patch.year}-$month-${patch.day.toString().padStart(2, '0')}"
}
