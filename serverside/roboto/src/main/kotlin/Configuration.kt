package at.asitplus.attestation

import com.sksamuel.hoplite.ArrayNode
import com.sksamuel.hoplite.BooleanNode
import com.sksamuel.hoplite.ConfigFailure
import com.sksamuel.hoplite.DecoderContext
import com.sksamuel.hoplite.DoubleNode
import com.sksamuel.hoplite.LongNode
import com.sksamuel.hoplite.MapNode
import com.sksamuel.hoplite.Node
import com.sksamuel.hoplite.NullNode
import com.sksamuel.hoplite.StringNode
import com.sksamuel.hoplite.Undefined
import com.sksamuel.hoplite.decoder.Decoder
import com.sksamuel.hoplite.decoder.NullHandlingDecoder
import com.sksamuel.hoplite.denormalize
import com.sksamuel.hoplite.fp.invalid
import com.sksamuel.hoplite.fp.valid
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.File
import java.io.FileReader
import java.io.FileWriter
import kotlin.reflect.KClass
import kotlin.reflect.KType

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
 * Writes the JSON representation of this [AttestationConfiguration] to the specified file.
 *
 * @param file The file to which the JSON representation of this configuration will be written.
 */
fun AttestationConfiguration.toJsonFile(file: File) = FileWriter(file).buffered().use { it.write(toJsonString()) }


/**
 * Writes the JSON representation of this [AttestationConfiguration] to the specified file.
 *
 * @param path The path to the file to which the JSON representation of this configuration will be written.
 */
fun AttestationConfiguration.toJsonFile(path: String) = toJsonFile(File(path))

/**
 * Serializes this `AttestationConfiguration` instance to a YAML-formatted string
 * and writes it to the specified file.
 *
 * @param file The destination file where the YAML representation of this configuration will be written.
 */
fun AttestationConfiguration.toYamlFile(file: File) = FileWriter(file).buffered().use { it.write(toYamlString()) }

/**
 * Serializes this `AttestationConfiguration` instance to a YAML-formatted string
 * and writes it to the specified file.
 *
 * @param path The destination path to the file where the YAML representation of this configuration will be written.
 */
fun AttestationConfiguration.toYamlFile(path: String) = toYamlFile(File(path))


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
 * Reads an attestation configuration from a YAML file and deserializes it into an instance of type [A].
 *
 * @param path The file system path to the YAML file containing the serialized attestation configuration.
 * @return An instance of type [A] representing the deserialized attestation configuration.
 */
fun <A : AttestationConfiguration> AttestationConfiguration.Reader<A>.fromYamlFile(path: String): A =
    fromYamlFile(File(path))


/**
 * Reads an attestation configuration of type [A] from a JSON file located at the specified path.
 *
 * @param file The JSON file containing the attestation configuration.
 * @return An instance of [A], created by parsing the JSON file's content.
 */
fun <A : AttestationConfiguration> AttestationConfiguration.Reader<A>.fromJsonFile(file: File): A =
    FileReader(file).buffered().use { fileReader ->
        fromJsonString(fileReader.readText())

    }

/**
 * Reads an attestation configuration of type [A] from a JSON file located at the specified path.
 *
 * @param path The file system path to the JSON file containing the attestation configuration.
 * @return An instance of [A], created by parsing the JSON file's content.
 */
fun <A : AttestationConfiguration> AttestationConfiguration.Reader<A>.fromJsonFile(path: String): A =
    fromJsonFile(File(path))

/**
 * Creates a Hoplite decoder for an [AttestationConfiguration] that converts the Hoplite node
 * into JSON and delegates to [AttestationConfiguration.Reader.fromJsonObject].
 *
 * Integrators can register this decoder with Hoplite to load any [AttestationConfiguration]
 * from arbitrary sources (files, env, etc) without using Kotlinx serialization directly.
 */
fun <A : AttestationConfiguration> AttestationConfiguration.Reader<A>.hopliteDecoder(
    targetClass: KClass<A>
): Decoder<A> = AttestationConfigurationHopliteDecoder(this, targetClass)

/**
 * Creates a Hoplite decoder for an [AttestationConfiguration] that converts the Hoplite node
 * into JSON and delegates to [AttestationConfiguration.Reader.fromJsonObject].
 */
inline fun <reified A : AttestationConfiguration> AttestationConfiguration.Reader<A>.hopliteDecoder(): Decoder<A> =
    hopliteDecoder(A::class)

private class AttestationConfigurationHopliteDecoder<A : AttestationConfiguration>(
    private val reader: AttestationConfiguration.Reader<A>,
    private val targetClass: KClass<A>
) : NullHandlingDecoder<A> {
    override fun supports(type: KType): Boolean = type.classifier == targetClass

    override fun safeDecode(node: Node, type: KType, context: DecoderContext) =
        runCatching {
            reader.fromJsonObject(hopliteNodeToJsonElement(node)).valid()
        }.getOrElse { ex ->
            ConfigFailure.Generic("Failed to decode ${targetClass.qualifiedName}: ${ex.message}").invalid()
        }
}

private fun hopliteNodeToJsonElement(node: Node): JsonElement = when (node) {
    is MapNode -> buildJsonObject {
        val denormalized = node.denormalize() as MapNode
        denormalized.map.forEach { (key, entry) ->
            put(key, hopliteNodeToJsonElement(entry))
        }
    }
    is ArrayNode -> buildJsonArray {
        node.elements.forEach { add(hopliteNodeToJsonElement(it)) }
    }
    is StringNode -> JsonPrimitive(node.value)
    is LongNode -> JsonPrimitive(node.value)
    is DoubleNode -> JsonPrimitive(node.value)
    is BooleanNode -> JsonPrimitive(node.value)
    is NullNode -> JsonNull
    Undefined -> JsonNull
}
