package examples.docs

import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.hopliteDecoder
import at.asitplus.attestation.supreme.SupremeConfiguration
import com.sksamuel.hoplite.ConfigLoaderBuilder
import com.sksamuel.hoplite.ExperimentalHoplite

@OptIn(ExperimentalHoplite::class)
@Suppress("UNUSED")
private fun readmeHopliteConfigExample() {


val loader = ConfigLoaderBuilder.default()
    .withExplicitSealedTypes()
    .addDecoder(AndroidAttestationConfiguration.hopliteDecoder())
    .addDecoder(IosAttestationConfiguration.hopliteDecoder())
    .addDecoder(SupremeConfiguration.hopliteDecoder())
    .build()

val config: SupremeConfiguration = loader.loadConfigOrThrow()






}
