package at.asitplus.warden.collector

import kotlinx.serialization.json.JsonObject

/** iOS uses App Attest (no Android key-attestation extension); the iOS target is build-only here. */
actual fun localAttestationExtensionJson(alias: String): JsonObject? = null
