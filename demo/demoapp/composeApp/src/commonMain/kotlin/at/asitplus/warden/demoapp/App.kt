package at.asitplus.warden.demoapp

import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import at.asitplus.attestation.supreme.AttestationClient
import at.asitplus.attestation.supreme.AttestationResponse
import at.asitplus.attestation.supreme.performAttestationFlow
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.asn1.encodeToPEM
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.supreme.os.PlatformSigningProvider
import com.multiplatform.webview.web.WebView
import com.multiplatform.webview.web.rememberWebViewNavigator
import com.multiplatform.webview.web.rememberWebViewState
import com.russhwolf.settings.Settings
import demoapp.composeapp.generated.resources.Res
import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.coroutines.launch
import kotlinx.serialization.Serializable
import org.jetbrains.compose.resources.ExperimentalResourceApi
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


@OptIn(ExperimentalMaterial3Api::class, ExperimentalResourceApi::class)
@Composable
@Preview
fun App(
    settings: Settings? = null // null for preview / tests
) {
    MaterialTheme(colorScheme = darkColorScheme()) {

        var idle by remember { mutableStateOf(true) }

        //The first IP is for using the emulator, the latter happened to be the IP of my dev machine.
        val default = if (getPlatform().name.contains("false")) "http://10.0.2.2:8080" else "http://192.168.101.23:8080"

        // Centralized state management for UI elements
        var baseUrl by rememberSaveable { mutableStateOf(default) }
        var getChallengeEndpoint by rememberSaveable { mutableStateOf("/api/v1/challenge") }
        var protectedEndpoint by rememberSaveable { mutableStateOf("/protected") }
        var connectionStatus by remember { mutableStateOf(ConnectionStatus.IDLE) }
        val errorLogs = remember { mutableStateListOf<String>() }

        val coroutineScope = rememberCoroutineScope()

        //ATTESTATION client init
        //ATTESTATION client init
        //ATTESTATION client init
        var http = HttpClient()
        val client = remember { AttestationClient(http) }
        //ATTESTATION client init
        //ATTESTATION client init
        //ATTESTATION client init

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
                    enabled = idle,
                    onTestConnection = {
                        connectionStatus = ConnectionStatus.LOADING
                        coroutineScope.launch {
                            idle = false
                            val result = catchingUnwrapped { http.get(baseUrl).status }
                            result.onSuccess {
                                connectionStatus = ConnectionStatus.SUCCESS
                            }.onFailure {
                                connectionStatus = ConnectionStatus.FAILURE
                                errorLogs.add(0, "Connectivity Test Failed: ${it.message ?: "Unknown error"}")
                            }
                            idle = true
                        }
                    }
                )
                val webViewState = rememberWebViewState("https://a-sit-plus.github.io/warden-supreme")
                val navigator = rememberWebViewNavigator()
                HorizontalDivider()

                // 2. Fetch to Preferences/Storage Section
                AttestationInteraction(
                    enabled = idle,
                    title = "Request Attestation",
                    endpoint = getChallengeEndpoint,
                    onEndpointChange = { getChallengeEndpoint = it },
                    buttonText = "Attest",
                    onDeleteClick = {
                        coroutineScope.launch {
                            idle = false
                            PlatformSigningProvider.deleteSigningKey(ALIAS)
                            settings?.deleteCertificateChain()
                            idle = true
                        }
                    },
                    onButtonClick = {
                        coroutineScope.launch {
                            idle = false
                            val fullUrl = baseUrl + getChallengeEndpoint

                            //ATTESTATION ALL-IN-ONE CALL
                            //ATTESTATION ALL-IN-ONE CALL
                            //ATTESTATION ALL-IN-ONE CALL
                            val result = catchingUnwrapped { client.performAttestationFlow(ALIAS, Url(fullUrl)) }
                            //ATTESTATION ALL-IN-ONE CALL
                            //ATTESTATION ALL-IN-ONE CALL
                            //ATTESTATION ALL-IN-ONE CALL

                            result.onSuccess { resp ->
                                when (resp) {
                                    is AttestationResponse.Failure -> {
                                        navigator.loadHtml(resp.explanation ?: "Attestation error: ${resp.kind}")
                                        idle = true
                                    }

                                    is AttestationResponse.Success -> {
                                        //tell the user it worked
                                        navigator.loadHtml(Res.readBytes("files/cert-issued.html").decodeToString())
                                        //delete old cert chain
                                        settings?.deleteCertificateChain()
                                        //store new one
                                        settings?.storeCertificateChain(resp.certificateChain)
                                        idle = true

                                    }
                                }
                            }.onFailure {
                                navigator.loadHtml(it.message ?: it::class.simpleName ?: "Attestation process failed")
                                it.printStackTrace()
                                idle = true
                            }

                        }
                    }
                )

                HorizontalDivider()


                EndpointInteractionSection(
                    title = "Access Resource",
                    endpoint = protectedEndpoint,
                    onEndpointChange = { protectedEndpoint = it },
                    buttonText = "Fetch",
                    enabled = idle,
                    onButtonClick = {
                        coroutineScope.launch {
                            idle = false
                            catchingUnwrapped {
                                //THIS IS JUST OUR DEMO AUTH FLOW
                                val result = http.get(baseUrl + protectedEndpoint) {
                                    accept(ContentType.Text.Plain)
                                    settings?.loadCertificateChain()?.let { chain ->
                                        bearerAuth(createJWT(ALIAS, chain).serialize())
                                    }
                                }
                                if (result.status == HttpStatusCode.Forbidden) {
                                    http.get(baseUrl + protectedEndpoint) {
                                        accept(ContentType.Any)
                                        settings?.loadCertificateChain()?.let { chain ->
                                            bearerAuth(createJWT(ALIAS, chain, result.bodyAsText()).serialize())
                                        }
                                    }.let {
                                        idle = true
                                        if (it.status.isSuccess()) navigator.loadHtml(it.bodyAsText())
                                        else
                                            navigator.loadHtml(it.toString() + "<br>" + it.bodyAsText())
                                    }

                                } else {
                                    idle = true
                                    if (result.status.isSuccess()) navigator.loadHtml(result.bodyAsText())
                                    else navigator.loadHtml(result.toString() + "<br>" + result.bodyAsText())
                                }

                            }.onFailure {
                                errorLogs.add(0, "access: ${it.message ?: "Unknown error"}")
                                navigator.loadHtml(it.message ?: "Unknown error")
                                idle = true

                            }
                        }
                    }
                )

                Column(Modifier.fillMaxSize()) {
                    Box(
                        Modifier
                            .weight(1f)
                            .fillMaxWidth()
                    ) {
                        WebView(
                            state = webViewState,
                            modifier = Modifier.fillMaxSize(),
                            navigator = navigator,
                        )
                    }
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
    onTestConnection: () -> Unit,
    enabled: Boolean = true,
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
        ElevatedButton(onClick = onTestConnection, enabled = enabled) {
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
    enabled: Boolean = true,
    onButtonClick: () -> Unit
) {
    val focusManager = LocalFocusManager.current
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
            ElevatedButton(onClick = {
                focusManager.clearFocus()

                onButtonClick()
            }, enabled = enabled) {
                Text(buttonText)
            }
        }
    }
}

/**
 * A reusable composable for an endpoint input field and a button.
 */
@Composable
private fun AttestationInteraction(
    title: String,
    endpoint: String,
    onEndpointChange: (String) -> Unit,
    buttonText: String,
    enabled: Boolean = true,
    onButtonClick: () -> Unit,
    onDeleteClick: () -> Unit,
) {
    val focusManager = LocalFocusManager.current
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
            ElevatedButton(onClick = {
                focusManager.clearFocus()

                onButtonClick()
            }, enabled = enabled) {
                Text(buttonText)
            }
            Button(enabled = enabled, onClick = onDeleteClick) {
                Text("Delete key")
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

