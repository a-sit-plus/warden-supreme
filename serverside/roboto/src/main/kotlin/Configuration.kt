package at.asitplus.attestation

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import java.io.File
import java.io.FileReader

interface AttestationConfiguration {

    /**
     * Serialises this config into its canonical form (JSON). Can be loaded using [Reader.fromJsonString] afterwards.
     */
    fun toJsonString(): String

    /**
     * Serialises this config into its canonical form (YAML). Can be loaded using [Reader.fromYamlString] afterwards.
     */
    fun toYamlString(): String

    /**
     * Serialises this config into a [JsonObject]. Can be loaded using [Reader.fromJsonObject] afterwards.
     */
    fun toJsonElement(): JsonObject


    interface Reader<A : AttestationConfiguration> {
        /**
         *  Loads the config from its canonical form (JSON), as produced by [toJsonString].
         */
        fun fromJsonString(jsonRepresentation: String): A

        /**
         * Loads the config from its canonical form (YAML), as produced by [toYamlString].
         */
        fun fromYamlString(yamlRepresentation: String): A

        /**
         * Loads the config from its canonical form (JSON), as produced by [toJsonElement].
         */
        fun fromJsonObject(jsonRepresentation: JsonElement): A
    }
}

/**
 * Reads an attestation configuration from a YAML file and deserializes it into an instance of type [A].
 *
 * @param path The file system path to the YAML file containing the serialized attestation configuration.
 * @return An instance of type [A] representing the deserialized attestation configuration.
 */
fun <A : AttestationConfiguration> AttestationConfiguration.Reader<A>.fromYamlFile(path: String): A =
    FileReader(path).buffered().use { fileReader ->
        fromYamlString(fileReader.readText())
    }
/**
 * Reads an attestation configuration from a YAML file and deserializes it into an instance of type [A].
 *
 * @param file The YAML file containing the serialized attestation configuration.
 * @return An instance of type [A] representing the deserialized attestation configuration.
 */
fun <A : AttestationConfiguration> AttestationConfiguration.Reader<A>.fromYamlFile(file: File): A =
    FileReader(file).buffered().use { fileReader ->
        fromYamlString(fileReader.readText())
    }

/**
 * Reads an attestation configuration of type [A] from a JSON file located at the specified path.
 *
 * @param path The file system path to the JSON file containing the attestation configuration.
 * @return An instance of [A], created by parsing the JSON file's content.
 */
fun <A : AttestationConfiguration> AttestationConfiguration.Reader<A>.fromJsonFile(path: String): A =
    FileReader(path).buffered().use { fileReader ->
        fromJsonFile(fileReader.readText())

    }
/**
 * Reads an attestation configuration of type [A] from a JSON file located at the specified path.
 *
 * @param file The JSON file containing the attestation configuration.
 * @return An instance of [A], created by parsing the JSON file's content.
 */
fun <A : AttestationConfiguration> AttestationConfiguration.Reader<A>.fromJsonFile(file: File): A =
    FileReader(file).buffered().use { fileReader ->
        fromJsonFile(fileReader.readText())

    }