package at.asitplus.warden.collector

import kotlinx.serialization.json.JsonObject

/**
 * Renders the Android key-attestation extension of the locally created keystore key [alias] as
 * human-readable JSON, or null if unavailable (iOS has no equivalent; the key may lack an
 * attestation; or nothing is stored under [alias]).
 */
expect fun localAttestationExtensionJson(alias: String): JsonObject?
