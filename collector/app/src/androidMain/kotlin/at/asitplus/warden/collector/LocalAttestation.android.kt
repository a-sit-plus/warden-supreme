package at.asitplus.warden.collector

import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.warden.collector.shared.androidAttestationJson
import kotlinx.serialization.json.JsonObject
import java.security.KeyStore

/**
 * Reads the attestation certificate chain the Android Keystore generated for [alias] and renders the
 * leaf's key-attestation extension. The chain is produced when the key is created with an attestation
 * challenge (as supreme-client does), so it is available right after an attestation run.
 */
actual fun localAttestationExtensionJson(alias: String): JsonObject? = runCatching {
    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val leaf = keyStore.getCertificateChain(alias)?.firstOrNull() ?: return@runCatching null
    Certificate.fromAsn1(leaf.encoded).androidAttestationJson()
}.getOrNull()
