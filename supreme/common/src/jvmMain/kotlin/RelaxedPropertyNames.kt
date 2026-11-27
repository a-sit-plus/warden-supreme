package at.asitplus.attestation

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PolymorphicKind
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.StructureKind
import kotlinx.serialization.json.*

fun JsonElement.withRelaxedPropertyNames(rootSerializer: KSerializer<*>): JsonElement =
    withRelaxedPropertyNames(rootSerializer.descriptor)

private fun JsonElement.withRelaxedPropertyNames(descriptor: SerialDescriptor?): JsonElement = when (this) {
    is JsonObject -> normalizeObject(descriptor)
    is JsonArray -> normalizeArray(descriptor)
    else -> this
}

private fun JsonObject.normalizeObject(declaredDescriptor: SerialDescriptor?): JsonObject {
    // YAML (yamlkt) writes sealed classes as `{type: X, value: {...}}`; JSON expects them flat.
    if (declaredDescriptor?.kind == PolymorphicKind.SEALED) flattenedSealedYamlForm()?.let {
        return it.normalizeObject(declaredDescriptor)
    }
    // Sealed hierarchies (e.g. KeyConstraints.AlgorithmParameters) only describe their subclasses indirectly; resolve the
    // concrete subclass from the discriminator, or camelCase properties such as `parameterSet` or `keySize` are lost
    // when a loader lowercases keys.
    val descriptor = declaredDescriptor?.sealedSubclassFor(this) ?: declaredDescriptor
    val descriptorInfo = descriptor?.objectDescriptorInfo()
    val mapValueDescriptor = descriptor?.mapValueDescriptor()

    return buildJsonObject {
        entries.forEach { (rawKey, rawValue) ->
            // When we have a concrete descriptor, emit its exact canonical field name.
            // Otherwise we still need a usable property name for descriptor-less pockets such as
            // polymorphic map-like payloads. Example: `proxy-config` must become `proxyConfig`,
            // not `proxyconfig`, or the downstream loader will miss the field entirely.
            val canonicalKey = descriptorInfo?.canonicalNameFor(rawKey) ?: rawKey.relaxedFallbackName()
            val childDescriptor = descriptorInfo?.childDescriptorFor(canonicalKey) ?: mapValueDescriptor
            put(canonicalKey, rawValue.withRelaxedPropertyNames(childDescriptor))
        }
    }
}

private fun JsonArray.normalizeArray(descriptor: SerialDescriptor?): JsonArray {
    val elementDescriptor = descriptor?.listElementDescriptor()
    return buildJsonArray {
        forEach { add(it.withRelaxedPropertyNames(elementDescriptor)) }
    }
}

private data class ObjectDescriptorInfo(
    private val canonicalNamesByFoldedAlias: Map<String, String>,
    private val childDescriptors: Map<String, SerialDescriptor>
) {
    fun canonicalNameFor(rawKey: String): String =
        canonicalNamesByFoldedAlias[rawKey.relaxedLookupToken()] ?: rawKey.relaxedFallbackName()

    fun childDescriptorFor(canonicalKey: String): SerialDescriptor? = childDescriptors[canonicalKey]
}

private fun SerialDescriptor.objectDescriptorInfo(): ObjectDescriptorInfo? {
    if (kind !is StructureKind.CLASS && kind !is StructureKind.OBJECT) return null

    val foldedAliases = buildMap(elementsCount) {
        repeat(elementsCount) { index ->
            put(getElementName(index).relaxedLookupToken(), getElementName(index))
        }
    }
    val childDescriptors = buildMap(elementsCount) {
        repeat(elementsCount) { index ->
            put(getElementName(index), getElementDescriptor(index))
        }
    }

    return ObjectDescriptorInfo(foldedAliases, childDescriptors)
}

/** The default class discriminator of kotlinx.serialization JSON, as used by all Warden configuration formats. */
private const val CLASS_DISCRIMINATOR = "type"

/** `{type: X, value: {a: 1}}` -> `{type: X, a: 1}`; `null` if this is not that shape. */
private fun JsonObject.flattenedSealedYamlForm(): JsonObject? {
    if (size != 2) return null
    val type = entries.firstOrNull { it.key.relaxedLookupToken() == CLASS_DISCRIMINATOR } ?: return null
    val value = entries.firstOrNull { it.key.relaxedLookupToken() == "value" }?.value as? JsonObject ?: return null
    if (value.keys.any { it.relaxedLookupToken() == CLASS_DISCRIMINATOR }) return null
    return JsonObject(mapOf(type.key to type.value) + value)
}

@OptIn(ExperimentalSerializationApi::class)
private fun SerialDescriptor.sealedSubclassFor(obj: JsonObject): SerialDescriptor? {
    if (kind != PolymorphicKind.SEALED || elementsCount < 2) return null
    val type = obj.entries.firstOrNull { it.key.relaxedLookupToken() == CLASS_DISCRIMINATOR }
        ?.value?.let { it as? JsonPrimitive }?.contentOrNull ?: return null
    val subclasses = getElementDescriptor(1)
    return (0 until subclasses.elementsCount)
        .firstOrNull { subclasses.getElementName(it) == type }
        ?.let(subclasses::getElementDescriptor)
}

private fun SerialDescriptor.listElementDescriptor(): SerialDescriptor? =
    if (kind == StructureKind.LIST) getElementDescriptor(0) else null

private fun SerialDescriptor.mapValueDescriptor(): SerialDescriptor? =
    if (kind == StructureKind.MAP) getElementDescriptor(1) else null

private fun String.relaxedLookupToken(): String =
    lowercase().replace("-", "").replace("_", "")

/**
 * Produces the property name that should be written back into the normalized JSON tree when
 * relaxed matching cannot consult an authoritative serializer descriptor.
 *
 * This is intentionally different from [relaxedLookupToken]:
 * - [relaxedLookupToken] is only for comparison and destroys formatting
 * - this function must emit a usable property name for downstream deserializers
 *
 * Concrete examples:
 * - `proxy-config` -> `proxyConfig`
 * - `proxy_config` -> `proxyConfig`
 * - `proxyConfig` -> `proxyConfig`
 * - `GENERICDEVICENAMEOID` -> `genericdevicenameoid`
 *
 * The fallback matters for descriptor-less subtrees such as polymorphic configuration pockets.
 * If we emitted the lookup token instead, `proxy-config` would become `proxyconfig`, which would
 * no longer match the actual Kotlin property `proxyConfig`.
 */
private fun String.relaxedFallbackName(): String =
    if ('-' !in this && '_' !in this) {
        if (any(Char::isLowerCase) || none(Char::isLetter)) this else lowercase()
    }
    else {
        val segments = relaxedKeySegments()
        // Preserve separator-only junk like "---" instead of collapsing it to "",
        // so it still fails as an unknown key rather than turning into a synthetic empty name.
        if (segments.isEmpty()) this
        else buildString {
            append(segments.first())
            segments.drop(1).forEach { append(it.replaceFirstChar(Char::uppercaseChar)) }
        }
    }


private fun String.relaxedKeySegments(): List<String> =
    split('-', '_').filter { it.isNotEmpty() }.map(String::lowercase)
