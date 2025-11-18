package at.asitplus.warden.demoapp

import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import at.asitplus.attestation.supreme.AttestationClient
import at.asitplus.attestation.supreme.AttestationResponse
import at.asitplus.attestation.supreme.attestationEndpointUrl
import at.asitplus.attestation.supreme.createAttestationProof
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.asn1.encodeToPEM
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.supreme.os.PlatformSigningProvider
import com.multiplatform.webview.web.WebView
import com.multiplatform.webview.web.rememberWebViewNavigator
import com.multiplatform.webview.web.rememberWebViewState
import com.russhwolf.settings.Settings
import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.coroutines.launch
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.jetbrains.compose.ui.tooling.preview.Preview

// Enum to represent the connectivity status
enum class ConnectionStatus {
    IDLE, // Initial state, gray
    SUCCESS, // Connection successful, green
    FAILURE, // Connection failed, red
    LOADING // Connection in progress, show spinner
}

const val ALIAS = "SUPREME_KEY"

@Serializable
data class TestSer(val x: Int)


@OptIn(ExperimentalMaterial3Api::class)
@Composable
@Preview
fun App(
    settings: Settings? = null // null for preview / tests
) {
    MaterialTheme(colorScheme = darkColorScheme()) {

        val default = if (getPlatform().name.contains("false")) "http://10.0.2.2:8080" else "http://10.6.252.4:8080"

        // Centralized state management for UI elements
        var baseUrl by rememberSaveable { mutableStateOf(default) }
        var getChallengeEndpoint by rememberSaveable { mutableStateOf("/api/v1/challenge") }
        var relativeEndpointForWebview by rememberSaveable { mutableStateOf("/") }
        var connectionStatus by remember { mutableStateOf(ConnectionStatus.IDLE) }
        val errorLogs = remember { mutableStateListOf<String>() }

        val coroutineScope = rememberCoroutineScope()
        val http = remember { HttpClient() }


        //TODO: Configure attestationClient


        // State for the bottom sheet (error log drawer)
        val scaffoldState = rememberBottomSheetScaffoldState(
            bottomSheetState = rememberStandardBottomSheetState(initialValue = SheetValue.PartiallyExpanded)
        )

        BottomSheetScaffold(
            scaffoldState = scaffoldState,
            sheetContent = {
                // Content of the error log drawer
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Icon(Icons.Default.ArrowUpward, contentDescription = "Pull up to see logs")
                    Text("Error Logs", style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(8.dp))
                    LazyColumn(modifier = Modifier.fillMaxSize()) {
                        items(errorLogs) { log ->
                            Text(log, modifier = Modifier.padding(4.dp), fontSize = 12.sp)
                        }
                    }
                }
            },
            sheetPeekHeight = 50.dp,
        ) { paddingValues ->
            // Main application content
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(paddingValues) // Respect padding from the scaffold
                    .padding(16.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {

                // 1. Connectivity Test Section
                ConnectivitySection(
                    baseUrl = baseUrl,
                    onBaseUrlChange = { baseUrl = it },
                    connectionStatus = connectionStatus,
                    onTestConnection = {
                        connectionStatus = ConnectionStatus.LOADING
                        coroutineScope.launch {
                            val result = catchingUnwrapped { http.get(baseUrl).status }
                            result.onSuccess {
                                connectionStatus = ConnectionStatus.SUCCESS
                            }.onFailure {
                                connectionStatus = ConnectionStatus.FAILURE
                                errorLogs.add(0, "Connectivity Test Failed: ${it.message ?: "Unknown error"}")
                            }
                        }
                    }
                )
                val webViewState = rememberWebViewState("about:blank")
                val navigator = rememberWebViewNavigator()
                Divider()

                Button(onClick = {
                    coroutineScope.launch {
                        PlatformSigningProvider.deleteSigningKey(ALIAS)
                        settings?.deleteCertificateChain()
                    }
                }) {
                    Text("Delete key")
                }
                // 2. Fetch to Preferences/Storage Section
                EndpointInteractionSection(
                    title = "Fetch and Store",
                    endpoint = getChallengeEndpoint,
                    onEndpointChange = { getChallengeEndpoint = it },
                    buttonText = "Attest",
                    onButtonClick = {
                        coroutineScope.launch {
                            val fullUrl = baseUrl + getChallengeEndpoint

                            //TODO fetch challenge, attest and store cert

                        }
                    }
                )

                Divider()


                EndpointInteractionSection(
                    title = "Render in WebView",
                    endpoint = relativeEndpointForWebview,
                    onEndpointChange = { relativeEndpointForWebview = it },
                    buttonText = "Fetch & Render",
                    onButtonClick = {
                        coroutineScope.launch {
                            catchingUnwrapped {
                                val result = http.get(baseUrl + relativeEndpointForWebview) {
                                    accept(ContentType.Text.Plain)
                                    settings?.loadCertificateChain()?.let { chain ->
                                        bearerAuth(createJWT(ALIAS, chain).serialize())
                                    }
                                }
                                if (result.status == HttpStatusCode.Forbidden) {
                                    http.get(baseUrl + relativeEndpointForWebview) {
                                        accept(ContentType.Any)
                                        settings?.loadCertificateChain()?.let { chain ->
                                            bearerAuth(createJWT(ALIAS, chain, result.bodyAsText()).serialize())
                                        }
                                    }.let {
                                        if (it.status.isSuccess()) navigator.loadHtml(it.bodyAsText())
                                        else
                                            navigator.loadHtml(it.toString() + "<br>" + it.bodyAsText())
                                    }

                                } else {
                                    if (result.status.isSuccess()) navigator.loadHtml(result.bodyAsText())
                                    else navigator.loadHtml(result.toString() + "<br>" + result.bodyAsText())
                                }

                            }.onFailure {
                                println(Json.encodeToString(TestSer(42)))
                                it.printStackTrace()
                                errorLogs.add(0, "access: ${it.message ?: "Unknown error"}")

                            }
                        }
                    }
                )

                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .verticalScroll(rememberScrollState())
                ) {
                    // ... all your existing content ...

                    WebView(
                        state = webViewState,
                        modifier = Modifier.fillMaxSize(),
                        navigator = navigator
                    )
                }
            }
        }
    }
}

/**
 * A composable for the connectivity test UI.
 */
@Composable
private fun ConnectivitySection(
    baseUrl: String,
    onBaseUrlChange: (String) -> Unit,
    connectionStatus: ConnectionStatus,
    onTestConnection: () -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        OutlinedTextField(
            value = baseUrl,
            onValueChange = onBaseUrlChange,
            label = { Text("Base URL") },
            modifier = Modifier.weight(1f),
            singleLine = true
        )
        ElevatedButton(onClick = onTestConnection) {
            Text("Test")
        }
        ConnectionStatusIndicator(status = connectionStatus)
    }
}

/**
 * A composable that displays a status indicator circle.
 */
@Composable
private fun ConnectionStatusIndicator(status: ConnectionStatus) {
    val color by animateColorAsState(
        targetValue = when (status) {
            ConnectionStatus.IDLE -> Color.Gray
            ConnectionStatus.SUCCESS -> Color.Green
            ConnectionStatus.FAILURE -> Color.Red
            ConnectionStatus.LOADING -> MaterialTheme.colorScheme.primary
        }
    )

    if (status == ConnectionStatus.LOADING) {
        CircularProgressIndicator(modifier = Modifier.size(24.dp), strokeWidth = 2.dp)
    } else {
        Box(
            modifier = Modifier
                .size(24.dp)
                .clip(CircleShape)
                .background(color)
        )
    }
}

/**
 * A reusable composable for an endpoint input field and a button.
 */
@Composable
private fun EndpointInteractionSection(
    title: String,
    endpoint: String,
    onEndpointChange: (String) -> Unit,
    buttonText: String,
    onButtonClick: () -> Unit
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(title, style = MaterialTheme.typography.titleSmall)
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            OutlinedTextField(
                value = endpoint,
                onValueChange = onEndpointChange,
                label = { Text("Relative Endpoint") },
                modifier = Modifier.weight(1f),
                singleLine = true
            )
            ElevatedButton(onClick = onButtonClick) {
                Text(buttonText)
            }
        }
    }
}


private fun Settings.storeCertificateChain(chain: CertificateChain) {
    putString(
        "chain",
        chain.joinToString { it.encodeToPEM().getOrThrow() }
    )
}

private fun Settings.loadCertificateChain(): CertificateChain? = getString("chain", "").let {
    if (it.isNotEmpty()) {
        it.split(",").map { X509Certificate.decodeFromPem(it).getOrThrow() }
    } else null
}

private fun Settings.deleteCertificateChain() {
    remove("chain")
}


