package at.asitplus.warden.collector

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * A collapsible/expandable JSON tree over a parsed [JsonElement]. Containers start collapsed except
 * the root, so a large debug statement opens showing only its top-level keys; tap a row to drill in.
 * Rows never wrap ([softWrap] = false) — put this inside a horizontally + vertically scrollable box.
 */
@Composable
fun JsonTreeView(root: JsonElement, modifier: Modifier = Modifier) {
    Column(modifier) {
        JsonNode(name = null, element = root, depth = 0, initiallyExpanded = true)
    }
}

@Composable
private fun JsonNode(name: String?, element: JsonElement, depth: Int, initiallyExpanded: Boolean) {
    when (element) {
        is JsonObject ->
            ContainerNode(name, element.entries.map { it.key to it.value }, "{", "}", depth, initiallyExpanded)

        is JsonArray ->
            // Array elements render as a bare list of values (no "index": prefix).
            ContainerNode(name, element.map { null to it }, "[", "]", depth, initiallyExpanded)

        is JsonNull -> LeafNode(name, "null", depth, MaterialTheme.colorScheme.error)

        is JsonPrimitive ->
            if (element.isString) LeafNode(name, "\"${element.content}\"", depth, MaterialTheme.colorScheme.tertiary)
            else LeafNode(name, element.content, depth, MaterialTheme.colorScheme.secondary)
    }
}

@Composable
private fun ContainerNode(
    name: String?,
    children: List<Pair<String?, JsonElement>>,
    open: String,
    close: String,
    depth: Int,
    initiallyExpanded: Boolean,
) {
    var expanded by remember { mutableStateOf(initiallyExpanded) }

    Row(Modifier.clickable { expanded = !expanded }.padding(vertical = 1.dp)) {
        Indent(depth)
        Mono(if (expanded) "▼ " else "▶ ", MaterialTheme.colorScheme.onSurfaceVariant)
        if (name != null) Mono("\"$name\": ", WardenPalette.Cyan)
        Mono(
            if (expanded) open else "$open … $close  (${children.size})",
            MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }

    if (expanded) {
        children.forEach { (childName, childEl) ->
            JsonNode(childName, childEl, depth + 1, initiallyExpanded = false)
        }
        Row(Modifier.padding(vertical = 1.dp)) {
            Indent(depth)
            Mono(close, MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun LeafNode(name: String?, value: String, depth: Int, valueColor: Color) {
    Row(Modifier.padding(vertical = 1.dp)) {
        Indent(depth)
        if (name != null) Mono("\"$name\": ", WardenPalette.Cyan)
        Mono(value, valueColor)
    }
}

@Composable
private fun Indent(depth: Int) {
    if (depth > 0) Mono("  ".repeat(depth), MaterialTheme.colorScheme.surfaceVariant)
}

@Composable
private fun Mono(text: String, color: Color) {
    Text(
        text = text,
        color = color,
        fontFamily = FontFamily.Monospace,
        fontSize = 13.sp,
        softWrap = false,
    )
}
