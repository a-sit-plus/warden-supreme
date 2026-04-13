package at.asitplus.attestation

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.StructureKind
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

fun JsonElement.withRelaxedPropertyNames(rootSerializer: KSerializer<*>): JsonElement =
    withRelaxedPropertyNames(rootSerializer.descriptor)

private fun JsonElement.withRelaxedPropertyNames(descriptor: SerialDescriptor?): JsonElement = when (this) {
    is JsonObject -> normalizeObject(descriptor)
    is JsonArray -> normalizeArray(descriptor)
    else -> this
}

private fun JsonObject.normalizeObject(descriptor: SerialDescriptor?): JsonObject {
    val descriptorInfo = descriptor?.objectDescriptorInfo()
    val mapValueDescriptor = descriptor?.mapValueDescriptor()

    return buildJsonObject {
        entries.forEach { (rawKey, rawValue) ->
            val canonicalKey = descriptorInfo?.canonicalNameFor(rawKey) ?: rawKey.toRelaxedFallbackName()
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
        canonicalNamesByFoldedAlias[rawKey.foldForRelaxedLookup()] ?: rawKey.toRelaxedFallbackName()

    fun childDescriptorFor(canonicalKey: String): SerialDescriptor? = childDescriptors[canonicalKey]
}

private fun SerialDescriptor.objectDescriptorInfo(): ObjectDescriptorInfo? {
    if (kind !is StructureKind.CLASS && kind !is StructureKind.OBJECT) return null

    val foldedAliases = buildMap(elementsCount) {
        repeat(elementsCount) { index ->
            put(getElementName(index).foldForRelaxedLookup(), getElementName(index))
        }
    }
    val childDescriptors = buildMap(elementsCount) {
        repeat(elementsCount) { index ->
            put(getElementName(index), getElementDescriptor(index))
        }
    }

    return ObjectDescriptorInfo(foldedAliases, childDescriptors)
}

private fun SerialDescriptor.listElementDescriptor(): SerialDescriptor? =
    if (kind == StructureKind.LIST) getElementDescriptor(0) else null

private fun SerialDescriptor.mapValueDescriptor(): SerialDescriptor? =
    if (kind == StructureKind.MAP) getElementDescriptor(1) else null

private fun String.foldForRelaxedLookup(): String =
    lowercase().filter(Char::isLetterOrDigit)

private fun String.toRelaxedFallbackName(): String {
    if (none { !it.isLetterOrDigit() }) {
        return if (any(Char::isLowerCase) || none(Char::isLetter)) this else lowercase()
    }

    val parts = split(RELAXED_NAME_SEPARATOR_REGEX).filter(String::isNotBlank)
    if (parts.isEmpty()) return this

    return buildString {
        append(parts.first().lowercase())
        parts.drop(1).forEach { part ->
            append(part.lowercase().replaceFirstChar(Char::titlecase))
        }
    }
}

private val RELAXED_NAME_SEPARATOR_REGEX = Regex("[^A-Za-z0-9]+")
