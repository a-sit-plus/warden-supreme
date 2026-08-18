package at.asitplus.warden.collector

import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.IconButton
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import at.asitplus.attestation.supreme.AttestationClient
import at.asitplus.attestation.supreme.AttestationResponse
import at.asitplus.attestation.supreme.createAttestationProof
import at.asitplus.catchingUnwrapped
import at.asitplus.io.MultiBase
import at.asitplus.signum.supreme.os.PlatformSigningProvider
import at.asitplus.warden.collector.generated.resources.Res
import at.asitplus.warden.collector.generated.resources.warden
import at.asitplus.warden.collector.shared.DemoAttestation
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.Url
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.TimeSource
import org.jetbrains.compose.resources.painterResource

private const val ALIAS = "collectorDemoKey"

@Composable
fun App() {
    WardenTheme {
        val scope = rememberCoroutineScope()
        val actions = rememberPlatformActions()
        val endpointStore = rememberEndpointStore()
        val defaultEndpoint = endpointStore.defaultEndpoint
        // Persisted across launches; falls back to the emulator default.
        var endpoint by remember { mutableStateOf(endpointStore.get() ?: defaultEndpoint) }
        var status by remember { mutableStateOf("Enter the backend domain and press Attest.") }
        var attestationJson by remember { mutableStateOf<JsonElement?>(null) }
        var debugJson by remember { mutableStateOf<JsonElement?>(null) }
        var rawDetail by remember { mutableStateOf<String?>(null) }
        var busy by remember { mutableStateOf(false) }
        var update by remember { mutableStateOf<Pair<String, Long>?>(null) }

        LaunchedEffect(endpoint) {
            delay(500)
            val host = backendHost(endpoint) ?: return@LaunchedEffect
            catchingUnwrapped {
                val client = HttpClient()
                try {
                    client.get(host + DemoAttestation.VERSION_PATH).bodyAsText().trim().toLong()
                } finally {
                    client.close()
                }
            }.getOrNull()?.takeIf { it > actions.appVersionCode }?.let {
                update = host to it
            }
        }

        update?.let { (host, version) ->
            AlertDialog(
                onDismissRequest = { update = null },
                title = { Text("Update available") },
                text = { Text("Version $version is available. Install it now?") },
                confirmButton = {
                    TextButton(onClick = {
                        update = null
                        actions.openUrl(host + DemoAttestation.DOWNLOAD_PATH)
                    }) { Text("Update") }
                },
                dismissButton = {
                    TextButton(onClick = { update = null }) { Text("Ignore") }
                },
            )
        }

        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(MaterialTheme.colorScheme.background),
        ) {
            // Starfield: static idle, warps while a request is in flight.
            StarfieldBackground(warp = busy, modifier = Modifier.fillMaxSize())

            // Content sits on a Box (not a Surface), so give it a light default text color.
            CompositionLocalProvider(LocalContentColor provides MaterialTheme.colorScheme.onBackground) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    // Immersive full-screen: only avoid a display cutout, not the hidden system bars
                    // (safeContentPadding would still reserve their gesture-inset heights → a bottom gap).
                    .windowInsetsPadding(WindowInsets.displayCutout)
                    .padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text("Supreme Attestation Collector", style = MaterialTheme.typography.headlineSmall)

                OutlinedTextField(
                    value = endpoint,
                    onValueChange = { endpoint = it; endpointStore.set(it) },
                    label = { Text("Backend domain") },
                    singleLine = true,
                    enabled = !busy,
                    trailingIcon = {
                        if (endpoint != defaultEndpoint) {
                            IconButton(
                                enabled = !busy,
                                onClick = { endpoint = defaultEndpoint; endpointStore.set(defaultEndpoint) },
                            ) {
                                Text("⟲") // reset to default
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                )

                Button(
                    enabled = !busy,
                    onClick = {
                        busy = true
                        status = "Fetching challenge, attesting, requesting certificate…"
                        attestationJson = null
                        debugJson = null
                        rawDetail = null
                        scope.launch {
                            val start = TimeSource.Monotonic.markNow()
                            val result = catchingUnwrapped {
                                withContext(Dispatchers.Default) {
                                    PlatformSigningProvider.deleteSigningKey(ALIAS)
                                    val client = AttestationClient(HttpClient())
                                    val host = backendHost(endpoint) ?: error("Invalid backend domain")
                                    val challengeUrl = Url(host + DemoAttestation.CHALLENGE_PATH)
                                    val challenge = client.getChallenge(challengeUrl).getOrThrow()
                                    val proof = challenge.createAttestationProof(ALIAS) { emptyList() }.getOrThrow()
                                    // Submit the proof to the SAME origin the challenge came from — not the
                                    // attestationEndpoint embedded in the challenge (the backend's publicBaseUrl,
                                    // e.g. the 10.0.2.2 emulator address), which is unreachable from a real device.
                                    val attestUrl = Url(
                                        "${challengeUrl.protocol.name}://${challengeUrl.host}:${challengeUrl.port}" +
                                            DemoAttestation.ATTEST_PATH
                                    )
                                    client.attest(proof, attestUrl)
                                }
                            }
                            val localAttestation = withContext(Dispatchers.Default) { localAttestationExtensionJson(ALIAS) }

                            // Compute the outcome first — don't touch UI state yet, so nothing renders early.
                            var newDebug: JsonElement? = null
                            var newRaw: String? = null
                            val newStatus = result.fold(
                                onSuccess = { response ->
                                    when (response) {
                                        is AttestationResponse.Success ->
                                            "✅ Attested. Received ${response.certificateChain.size} certificate(s)."

                                        is AttestationResponse.Failure -> {
                                            val decoded = response.explanation?.let {
                                                catchingUnwrapped { MultiBase.decode(it)?.decodeToString() }.getOrNull()
                                            }
                                            val parsed = decoded?.let { catchingUnwrapped { Json.parseToJsonElement(it) }.getOrNull() }
                                            if (parsed != null) newDebug = parsed
                                            else newRaw = decoded ?: response.explanation
                                            "❌ ${response.kind}"
                                        }
                                    }
                                },
                                onFailure = {
                                    newRaw = it.message ?: it.toString()
                                    "❌ ${it::class.simpleName}"
                                },
                            )

                            // Keep the warp on screen for at least 1s; add nothing if it already took longer.
                            val remaining = 1000.milliseconds - start.elapsedNow()
                            if (remaining.isPositive()) delay(remaining)

                            // Apply all outputs together so the result pane expands only now.
                            attestationJson = localAttestation
                            debugJson = newDebug
                            rawDetail = newRaw
                            status = newStatus
                            busy = false
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(if (busy) "Engaging…" else "Attest")
                }

                Text(status)

                val hasOutput = attestationJson != null || debugJson != null || rawDetail != null

                // The result pane and the logo split the remaining space via animated weights: weights
                // always fill the parent exactly (no gap) and scale to any screen size, while animating
                // gives a smooth expand/collapse.
                val paneWeight by animateFloatAsState(
                    targetValue = if (hasOutput) 1f else 0.0001f,
                    animationSpec = tween(durationMillis = 180, easing = FastOutSlowInEasing),
                    label = "paneWeight",
                )
                val logoWeight by animateFloatAsState(
                    targetValue = if (hasOutput) 0.08f else 1f,
                    animationSpec = tween(durationMillis = 180, easing = FastOutSlowInEasing),
                    label = "logoWeight",
                )
                val logoPadding by animateDpAsState(
                    targetValue = if (hasOutput) 4.dp else 24.dp,
                    animationSpec = tween(durationMillis = 180, easing = FastOutSlowInEasing),
                    label = "logoPadding",
                )
                val vScroll = rememberScrollState()
                val hScroll = rememberScrollState()

                // Output goes ABOVE the logo, so the logo stays the bottom-most element.
                Surface(
                    color = MaterialTheme.colorScheme.surface.copy(alpha = 0.82f),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(paneWeight),
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .verticalScroll(vScroll)
                            .horizontalScroll(hScroll)
                            .padding(12.dp),
                    ) {
                        attestationJson?.let {
                            SectionLabel("Key attestation (local key)")
                            JsonTreeView(it)
                        }
                        debugJson?.let {
                            if (attestationJson != null) Spacer(Modifier.height(20.dp))
                            SectionLabel("Debug statement (replay)")
                            JsonTreeView(it)
                        }
                        rawDetail?.let {
                            if (attestationJson != null || debugJson != null) Spacer(Modifier.height(20.dp))
                            SectionLabel("Detail")
                            SelectionContainer {
                                Text(it, fontFamily = FontFamily.Monospace, fontSize = 13.sp, softWrap = false)
                            }
                        }
                    }
                }

                WardenLogo(
                    padding = logoPadding,
                    onClick = {
                        actions.toast("Opening Warden Supreme docs…")
                        actions.openUrl("https://a-sit-plus.github.io/warden-supreme")
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(logoWeight),
                )

                Text(
                    text = "More open source by A-SIT Plus",
                    style = MaterialTheme.typography.bodySmall,
                    textDecoration = TextDecoration.Underline,
                    modifier = Modifier
                        .align(Alignment.CenterHorizontally)
                        .clickable { actions.openUrl("https://plus.a-sit.at/open-source.html") },
                )
            }
            }
        }
    }
}

internal fun backendHost(value: String): String? = catchingUnwrapped {
    val host = value.trim().trimEnd('/').let { if ("://" in it) it else "https://$it" }
    val url = Url(host)
    require(url.protocol.name == "http" || url.protocol.name == "https")
    require((url.encodedPath.isEmpty() || url.encodedPath == "/") && url.parameters.isEmpty())
    host
}.getOrNull()

@Composable
private fun WardenLogo(modifier: Modifier, padding: Dp = 24.dp, onClick: () -> Unit = {}) {
    val transition = rememberInfiniteTransition(label = "glow")
    val pulse by transition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1800, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "glowPulse",
    )
    Box(modifier.clickable(onClick = onClick), contentAlignment = Alignment.Center) {
        Canvas(Modifier.fillMaxSize()) {
            val radius = size.minDimension * (0.5f + 0.1f * pulse)
            drawCircle(
                brush = Brush.radialGradient(
                    colors = listOf(
                        WardenPalette.LogoCyan.copy(alpha = 0.22f + 0.28f * pulse),
                        WardenPalette.LogoCyan.copy(alpha = 0.05f + 0.08f * pulse),
                        Color.Transparent,
                    ),
                    center = center,
                    radius = radius,
                ),
                radius = radius,
                center = center,
            )
        }
        Image(
            painter = painterResource(Res.drawable.warden),
            contentDescription = "Warden Supreme",
            contentScale = ContentScale.Fit,
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        )
    }
}

@Composable
private fun SectionLabel(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleSmall,
        modifier = Modifier.padding(bottom = 4.dp),
    )
}
