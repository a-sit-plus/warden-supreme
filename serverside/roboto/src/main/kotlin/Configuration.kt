package at.asitplus.attestation

import at.asitplus.attestation.android.AndroidAttestationConfiguration.Companion.fromJsonObject
import at.asitplus.attestation.android.AndroidAttestationConfiguration.Companion.fromJsonString
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

interface AttestationConfiguration {

    /**
     * Serialises this config into its canonical form (JSON). Can be loaded using [fromJsonString] afterwards.
     */
    fun toJsonString(): String

    /**
     * Serialises this config into its canonical form (YAML). Can be loaded using [fromJsonString] afterwards.
     */
    fun toYamlString(): String

    /**
     * Serialises this config into a [JsonObject]. Can be loaded using [fromJsonObject] afterwards.
     */
    fun toJsonElement(): JsonObject


    interface Reader<A : AttestationConfiguration> {
        /**
         *  Loads the config from its canonical form (JSON), as produced by [toJsonString].
         */
        fun fromJsonString(jsonRepresentation: String): A

        /**
         * Loads the config from its canonical form (JSON), as produced by [toJsonString].
         */
        fun fromYamlString(yamlRepresentation: String): A

        /**
         * Loads the config from its canonical form (JSON), as produced by [toJsonElement].
         */
        fun fromJsonObject(jsonRepresentation: JsonElement): A
    }
}