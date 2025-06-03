package at.asitplus.attestation

import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.PatchLevel
import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.attestation.data.AttestationData
import at.asitplus.signum.indispensable.Attestation
import com.google.android.attestation.ParsedAttestationRecord
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.booleans.shouldBeFalse
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldNotBeInstanceOf
import kotlinx.datetime.toKotlinInstant
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromStream
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes


@OptIn(ExperimentalStdlibApi::class)
class WardenTest : FreeSpec() {

    private val theGood = androidGood + iosGood

    init {
        "iosIDA" {
            val iosIDA = AttestationData(
                "ida",
                "Q049ODBlZDdlMjk4NzM3NWVmYjFhYWJhMDhjNjFjM2E3ZGIsTz1FSUQtREVWLVBLSSxPVT1ULUVudg==",
                listOf(
                    "o2NmbXRvYXBwbGUtYXBwYXR0ZXN0Z2F0dFN0bXSiY3g1Y4JZAuwwggLoMIICbaADAgECAgYBioRZyjgwCgYIKoZ" +
                            "Izj0EAwIwTzEjMCEGA1UEAwwaQXBwbGUgQXBwIEF0dGVzdGF0aW9uIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAg" +
                            "MCkNhbGlmb3JuaWEwHhcNMjMwOTEwMTMwNjMxWhcNMjQwODEyMTE1OTMxWjCBkTFJMEcGA1UEAwxAMTY5MDI5MDVhZjY2YmQ4ZWI" +
                            "xOTA1NGUxZTI3ZmZhNzQzNDAxMDdhNTg0MTVjZDNkY2ZjYjcyOTQ1MGVmMTc5MzEaMBgGA1UECwwRQUFBIENlcnRpZmljYXRpb24" +
                            "xEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASdH1ghEXv" +
                            "8cqnSwSgpZKjN3otmKO3SZjJK4lIrCGNJyHBhCc2+ILK2Zn+A2VTQHb/ZpBSVtlnUEXzY06Zj+HDro4HxMIHuMAwGA1UdEwEB/wQ" +
                            "CMAAwDgYDVR0PAQH/BAQDAgTwMH4GCSqGSIb3Y2QIBQRxMG+kAwIBCr+JMAMCAQG/iTEDAgEAv4kyAwIBAb+JMwMCAQG/iTQmBCQ" +
                            "5Q1lISk5HNjQ0LmF0LmFzaXRwbHVzLm9lZ3YtZGVtby1hcHClBgQEc2tzIL+JNgMCAQW/iTcDAgEAv4k5AwIBAL+JOgMCAQAwGQY" +
                            "JKoZIhvdjZAgHBAwwCr+KeAYEBDE2LjIwMwYJKoZIhvdjZAgCBCYwJKEiBCC5MVpWrKvwhsiJXV+2xxdfJw71s8XTKJNOrnGp9wq" +
                            "Y0zAKBggqhkjOPQQDAgNpADBmAjEA63cDbQpgHRWJSm45XR8nWfg7XkquNB+OC7yN17X8naKQsiUOfudeCDtf69sq7f8YAjEAxCZ" +
                            "KyCXsAuc39sdiGOvAlA3yDZHAKQhHNdPWv/gfTx70VV3FAK/SLyVXxjo9+/FjWQJHMIICQzCCAcigAwIBAgIQCbrF4bxAGtnUU5W" +
                            "8OBoIVDAKBggqhkjOPQQDAzBSMSYwJAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwKQXBwbGU" +
                            "gSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODM5NTVaFw0zMDAzMTMwMDAwMDBaME8xIzAhBgNVBAMMGkFwcGx" +
                            "lIEFwcCBBdHRlc3RhdGlvbiBDQSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMHYwEAYHKoZIzj0" +
                            "CAQYFK4EEACIDYgAErls3oHdNebI1j0Dn0fImJvHCX+8XgC3qs4JqWYdP+NKtFSV4mqJmBBkSSLY8uWcGnpjTY71eNw+/oI4ynoB" +
                            "zqYXndG6jWaL2bynbMq9FXiEWWNVnr54mfrJhTcIaZs6Zo2YwZDASBgNVHRMBAf8ECDAGAQH/AgEAMB8GA1UdIwQYMBaAFKyREFM" +
                            "zvb5oQf+nDKnl+url5YqhMB0GA1UdDgQWBBQ+410cBBmpybQx+IR01uHhV3LjmzAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwM" +
                            "DaQAwZgIxALu+iI1zjQUCz7z9Zm0JV1A1vNaHLD+EMEkmKe3R+RToeZkcmui1rvjTqFQz97YNBgIxAKs47dDMge0ApFLDukT5k2N" +
                            "lU/7MKX8utN+fXr5aSsq2mVxLgg35BDhveAe7WJQ5t2dyZWNlaXB0WQ5eMIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglghkgBZQM" +
                            "EAgEFADCABgkqhkiG9w0BBwGggCSABIID6DGCBBkwLAIBAgIBAQQkOUNZSEpORzY0NC5hdC5hc2l0cGx1cy5vZWd2LWRlbW8tYXB" +
                            "wMIIC9gIBAwIBAQSCAuwwggLoMIICbaADAgECAgYBioRZyjgwCgYIKoZIzj0EAwIwTzEjMCEGA1UEAwwaQXBwbGUgQXBwIEF0dGV" +
                            "zdGF0aW9uIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjMwOTEwMTMwNjMxWhcNMjQ" +
                            "wODEyMTE1OTMxWjCBkTFJMEcGA1UEAwxAMTY5MDI5MDVhZjY2YmQ4ZWIxOTA1NGUxZTI3ZmZhNzQzNDAxMDdhNTg0MTVjZDNkY2Z" +
                            "jYjcyOTQ1MGVmMTc5MzEaMBgGA1UECwwRQUFBIENlcnRpZmljYXRpb24xEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkN" +
                            "hbGlmb3JuaWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASdH1ghEXv8cqnSwSgpZKjN3otmKO3SZjJK4lIrCGNJyHBhCc2+ILK" +
                            "2Zn+A2VTQHb/ZpBSVtlnUEXzY06Zj+HDro4HxMIHuMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgTwMH4GCSqGSIb3Y2QIBQR" +
                            "xMG+kAwIBCr+JMAMCAQG/iTEDAgEAv4kyAwIBAb+JMwMCAQG/iTQmBCQ5Q1lISk5HNjQ0LmF0LmFzaXRwbHVzLm9lZ3YtZGVtby1" +
                            "hcHClBgQEc2tzIL+JNgMCAQW/iTcDAgEAv4k5AwIBAL+JOgMCAQAwGQYJKoZIhvdjZAgHBAwwCr+KeAYEBDE2LjIwMwYJKoZIhvd" +
                            "jZAgCBCYwJKEiBCC5MVpWrKvwhsiJXV+2xxdfJw71s8XTKJNOrnGp9wqY0zAKBggqhkjOPQQDAgNpADBmAjEA63cDbQpgHRWJSm4" +
                            "5XR8nWfg7XkquNB+OC7yN17X8naKQsiUOfudeCDtf69sq7f8YAjEAxCZKyCXsAuc39sdiGOvAlA3yDZHAKQhHNdPWv/gfTx70VV3" +
                            "FAK/SLyVXxjo9+/FjMCgCAQQCAQEEIHIduJSc8yt6liLZb79UH0jD9QPThPlJta8fgBr/dBR6MGACAQUCAQEEWEQxTEp0ekgzbWp" +
                            "aS0pBU1YzNEYyVWJkbWMvSWpCZlVjRHp0MDlmaUkzQXlhT1RJVlhXdHd3V0RndnVvMXZXSmViWXNsR05yckhneUpuTXhIZGszUVR" +
                            "RPT0wDgIBBgIBAQQGQVRURVNUMA8CAQcCAQEEB3NhbmRib3gwIAIBDAIBAQQYMjAyMy0ENTA5LTExVDEzOjA2OjMxLjYxOVowIAI" +
                            "BFQIBAQQYMjAyMy0xMi0xMFQxMzowNjozMS42MTlaAAAAAAAAoIAwggOtMIIDVKADAgECAhB9zZlRLYx9zRYL3g44gXpCMAoGCCq" +
                            "GSM49BAMCMHwxMDAuBgNVBAMMJ0FwcGxlIEFwcGxpY2F0aW9uIEludGVncmF0aW9uIENBIDUgLSBHMTEmMCQGA1UECwwdQXBwbGU" +
                            "gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMB4XDTIzMDMwODE1MjkxN1o" +
                            "XDTI0MDQwNjE1MjkxNlowWjE2MDQGA1UEAwwtQXBwbGljYXRpb24gQXR0ZXN0YXRpb24gRnJhdWQgUmVjZWlwdCBTaWduaW5nMRM" +
                            "wEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNqYKGfvXdIprBu9vpxxCe0" +
                            "/10ulGXkYsERsGjIv5lZXSez5sbvVBHMCbOaU2B3TyAjdgn4es8v78f0qKeJ/EP2jggHYMIIB1DAMBgNVHRMBAf8EAjAAMB8GA1U" +
                            "dIwQYMBaAFNkX/ktnkDhLkvTbztVXgBQLjz3JMEMGCCsGAQUFBwEBBDcwNTAzBggrBgEFBQcwAYYnaHR0cDovL29jc3AuYXBwbGU" +
                            "uY29tL29jc3AwMy1hYWljYTVnMTAxMIIBHAYDVR0gBIIBEzCCAQ8wggELBgkqhkiG92NkBQEwgf0wgcMGCCsGAQUFBwICMIG2DIG" +
                            "zUmVsaWFuY2Ugb24gdGhpcyBjZXJ0aWZpY2F0ZSBieSBhbnkgcGFydHkgYXNzdW1lcyBhY2NlcHRhbmNlIG9mIHRoZSB0aGVuIGF" +
                            "wcGxpY2FibGUgc3RhbmRhcmQgdGVybXMgYW5kIGNvbmRpdGlvbnMgb2YgdXNlLCBjZXJ0aWZpY2F0ZSBwb2xpY3kgYW5kIGNlcnR" +
                            "pZmljYXRpb24gcHJhY3RpY2Ugc3RhdGVtZW50cy4wNQYIKwYBBQUHAgEWKWh0dHA6Ly93d3cuYXBwbGUuY29tL2NlcnRpZmljYXR" +
                            "lYXV0aG9yaXR5MB0GA1UdDgQWBBRM8aefEGGKGjlkzG3m2zsHYpd2vTAOBgNVHQ8BAf8EBAMCB4AwDwYJKoZIhvdjZAwPBAIFADA" +
                            "KBggqhkjOPQQDAgNHADBEAiB622TidZxPBRb/LEnb85AsLxEspneOUIIKdIOcrDub7AIgRTXHYCoyQE35KoFn/Je2cuAJmdQpipb" +
                            "nBcvtCXAXUI0wggL5MIICf6ADAgECAhBW+4PUK/+NwzeZI7Varm69MAoGCCqGSM49BAMDMGcxGzAZBgNVBAMMEkFwcGxlIFJvb3Q" +
                            "gQ0EgLSBHMzEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgN" +
                            "VBAYTAlVTMB4XDTE5MDMyMjE3NTMzM1oXDTM0MDMyMjAwMDAwMFowfDEwMC4GA1UEAwwnQXBwbGUgQXBwbGljYXRpb24gSW50ZWd" +
                            "yYXRpb24gQ0EgNSAtIEcxMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5" +
                            "jLjELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASSzmO9fYaxqygKOxzhr/sElICRrPYx36bLKDVvREvhIeV" +
                            "X3RKNjbqCfJW+Sfq+M8quzQQZ8S9DJfr0vrPLg366o4H3MIH0MA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUu7DeoVgziJq" +
                            "kipnevr3rr9rLJKswRgYIKwYBBQUHAQEEOjA4MDYGCCsGAQUFBzABhipodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAzLWFwcGx" +
                            "lcm9vdGNhZzMwNwYDVR0fBDAwLjAsoCqgKIYmaHR0cDovL2NybC5hcHBsZS5jb20vYXBwbGVyb290Y2FnMy5jcmwwHQYDVR0OBBY" +
                            "EFNkX/ktnkDhLkvTbztVXgBQLjz3JMA4GA1UdDwEB/wQEAwIBBjAQBgoqhkiG92NkBgIDBAIFADAKBggqhkjOPQQDAwNoADBlAjE" +
                            "AjW+mn6Hg5OxbTnOKkn89eFOYj/TaH1gew3VK/jioTCqDGhqqDaZkbeG5k+jRVUztAjBnOyy04eg3B3fL1ex2qBo6VTs/NWrIxea" +
                            "SsOFhvoBJaeRfK6ls4RECqsxh2Ti3c0owggJDMIIByaADAgECAggtxfyI0sVLlTAKBggqhkjOPQQDAzBnMRswGQYDVQQDDBJBcHB" +
                            "sZSBSb290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmM" +
                            "uMQswCQYDVQQGEwJVUzAeFw0xNDA0MzAxODE5MDZaFw0zOTA0MzAxODE5MDZaMGcxGzAZBgNVBAMMEkFwcGxlIFJvb3QgQ0EgLSB" +
                            "HMzEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlV" +
                            "TMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEmOkvPUBypO2TInKBExzdEJXxxaNOcdwUFtkO5aYFKndke19OONO7HES1f/UftjJiXcn" +
                            "phFtPME8RWgD9WFgMpfUPLE0HRxN12peXl28xXO0rnXsgO9i5VNlemaQ6UQoxo0IwQDAdBgNVHQ4EFgQUu7DeoVgziJqkipnevr3" +
                            "rr9rLJKswDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaAAwZQIxAIPpwcQWXhpdNBjZ7e/0bA4" +
                            "ARku437JGEcUP/eZ6jKGma87CA9Sc9ZPGdLhq36ojFQIwbWaKEMrUDdRPzY1DPrSKY6UzbuNt2he3ZB/IUyb5iGJ0OQsXW8tRqAz" +
                            "oGAPnorIoAAAxgf0wgfoCAQEwgZAwfDEwMC4GA1UEAwwnQXBwbGUgQXBwbGljYXRpb24gSW50ZWdyYXRpb24gQ0EgNSAtIEcxMSY" +
                            "wJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMCEH3" +
                            "NmVEtjH3NFgveDjiBekIwDQYJYIZIAWUDBAIBBQAwCgYIKoZIzj0EAwIERzBFAiEA0M3dVXm17lZ/BwnJelyE3aUKrDtr+97vE+E" +
                            "RH4bpOXYCIC8wQw9814hOPb4vH0PKLltwBJWfdN9TWzF7zIyl53IOAAAAAAAAaGF1dGhEYXRhWKSOJJVLWqwLfKJFr4bDc2sg9nR" +
                            "b2kGynH4pvBeW43Kp5UAAAAAAYXBwYXR0ZXN0ZGV2ZWxvcAAgFpApBa9mvY6xkFTh4n/6dDQBB6WEFc09z8tylFDvF5OlAQIDJiA" +
                            "BIVggnR9YIRF7/HKp0sEoKWSozd6LZijt0mYySuJSKwhjScgiWCBwYQnNviCytmZ/gNlU0B2/2aQUlbZZ1BF82NOmY/hw6w==",
                    "omlzaWduYXR1cmVYSDBGAiEAjLQRt6NtttWQPfVSZpZqjAOfG0snhMtoGz/DflZPxDgCIQCq11k3Kmua6MKCPF/w" +
                            "9R0HW4Qprd+PVoFS1oQFrFO9pHFhdXRoZW50aWNhdG9yRGF0YVgljiSVS1qsC3yiRa+Gw3NrIPZ0W9pBspx+KbwXluNyqeVAAAAA" +
                            "AQ=="
                ),
                "2023-09-11T13:06:32Z",
                pubKeyB64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFT1XwEeF8NftY84GfnqTFBoxHNkdG7wZHcOkLKwT4W6333Jqmga1XkKySq/ApnslBPNZE1Os363SAv8X85ZIrQ=="
            )

            Warden(
                AndroidAttestationConfiguration.Builder(
                    AndroidAttestationConfiguration.AppData(
                        "foo",
                        listOf(byteArrayOf())
                    )
                ).build(),
                IOSAttestationConfiguration(
                    IOSAttestationConfiguration.AppData(
                        "9CYHJNG644",
                        "at.asitplus.oegv-demo-app",
                        sandbox = true
                    )
                ), FixedTimeClock(iosIDA.verificationDate.toInstant().toKotlinInstant())
            ).apply {
                verifyKeyAttestation(
                    iosIDA.attestationProof, iosIDA.challenge, iosIDA.publicKey!!
                ).apply {
                    isSuccess.shouldBeTrue()
                    verifyKeyAttestation(
                        iosIDA.attestationProof,
                        iosIDA.challenge,
                        iosIDA.pubKeyB64!!.decodeBase64ToArray()
                    ) shouldBe this
                }
            }
        }

        "The Good" - {
            theGood.forEach { recordedAttestation ->
                recordedAttestation.name - {
                    "OK" - {
                        "no version check" - {
                            attestationService(
                                androidVersion = null,
                                iosVersion = null,
                                iosBundleIdentifier = recordedAttestation.packageOverride
                                    ?: DEFAULT_IOS_ATTESTATION_CFG.applications.first().bundleIdentifier,
                                iosSandbox = !(recordedAttestation.isProductionOverride
                                    ?: !DEFAULT_IOS_ATTESTATION_CFG.applications.first().sandbox),
                                timeSource = FixedTimeClock(
                                    recordedAttestation.verificationDate.toInstant().toKotlinInstant()
                                ),
                                androidAttestationStatementValidity = 10.hours
                            ).apply {
                                "Generic" {
                                    verifyAttestation(
                                        recordedAttestation.attestationProof,
                                        recordedAttestation.challenge
                                    ).apply {
                                        also { println(it) }
                                        shouldNotBeInstanceOf<AttestationResult.Error>()
                                    }
                                    val dbg = collectDebugInfo(
                                        recordedAttestation.attestationProof,
                                        recordedAttestation.challenge
                                    ).serializeCompact()
                                    val replayGenericAttestation =
                                        WardenDebugAttestationStatement.deserializeCompact(dbg)
                                            .replayGenericAttestation(ignoreProxy = false)
                                    replayGenericAttestation shouldBe WardenDebugAttestationStatement.deserializeCompact(
                                        dbg
                                    )
                                        .replaySmart(ignoreProxy = false)
                                    replayGenericAttestation
                                        .shouldNotBeInstanceOf<AttestationResult.Error>()
                                }
                                "Key Attestation" {
                                    (verifyKeyAttestation(
                                        recordedAttestation.attestationProof,
                                        recordedAttestation.challenge,
                                        recordedAttestation.publicKey!!
                                    ) to verifyKeyAttestation(
                                        recordedAttestation.attestationProof,
                                        recordedAttestation.challenge,
                                        recordedAttestation.pubKeyB64!!.decodeBase64ToArray()
                                    )).apply {
                                        also { println(it.first) }
                                        first.isSuccess.shouldBeTrue()
                                        first.attestedPublicKey.shouldNotBeNull()
                                        first.attestedPublicKey!!.encoded shouldBe recordedAttestation.publicKey?.encoded
                                        first shouldBe second
                                    }

                                    val dbg = collectDebugInfo(
                                        recordedAttestation.attestationProof,
                                        recordedAttestation.challenge,
                                        recordedAttestation.publicKey!!
                                    ).serializeCompact()
                                    val replayKeyAttestationLegacy =
                                        WardenDebugAttestationStatement.deserializeCompact(dbg)
                                            .replayKeyAttestationLegacy(ignoreProxy = false)
                                    replayKeyAttestationLegacy shouldBe WardenDebugAttestationStatement.deserializeCompact(
                                        dbg
                                    )
                                        .replaySmart(ignoreProxy = false)
                                    replayKeyAttestationLegacy
                                        .shouldNotBeInstanceOf<AttestationResult.Error>()
                                }
                            }
                        }

                        "time drift" - {
                            withData(nameFn = {
                                "${
                                    recordedAttestation.verificationDate.toInstant().toKotlinInstant()
                                } + ${it.toIsoString()}"
                            }, 3000.days, (-3000).days) { leeway ->
                                val attestationService = attestationService(
                                    iosBundleIdentifier = recordedAttestation.packageOverride
                                        ?: DEFAULT_IOS_ATTESTATION_CFG.applications.first().bundleIdentifier,
                                    iosSandbox = !(recordedAttestation.isProductionOverride
                                        ?: !DEFAULT_IOS_ATTESTATION_CFG.applications.first().sandbox),
                                    androidPatchLevel = null,
                                    timeSource = FixedTimeClock(
                                        recordedAttestation.verificationDate.toInstant().toKotlinInstant() - leeway
                                    ),
                                    offset = leeway,
                                )
                                attestationService.verifyAttestation(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).apply {
                                    shouldNotBeInstanceOf<AttestationResult.Error>()
                                }
                                val dbg = attestationService.collectDebugInfo(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).serializeCompact()
                                val replayGenericAttestation =
                                    WardenDebugAttestationStatement.deserializeCompact(dbg)
                                        .replayGenericAttestation(ignoreProxy = false)
                                replayGenericAttestation shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                    .replaySmart(ignoreProxy = false)
                                replayGenericAttestation
                                    .shouldNotBeInstanceOf<AttestationResult.Error>()
                            }
                        }
                    }

                    "Fail" - {

                        "time of verification" - {
                            "too early" {
                                val attestationService = attestationService(
                                    iosBundleIdentifier = recordedAttestation.packageOverride
                                        ?: DEFAULT_IOS_ATTESTATION_CFG.applications.first().bundleIdentifier,
                                    iosSandbox = !(recordedAttestation.isProductionOverride
                                        ?: !DEFAULT_IOS_ATTESTATION_CFG.applications.first().sandbox),
                                    unlockedBootloaderAllowed = false,
                                    timeSource = FixedTimeClock(
                                        recordedAttestation.verificationDate.toInstant()
                                            .toKotlinInstant() - 3000.days
                                    ),
                                )
                                attestationService.verifyAttestation(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).shouldBeInstanceOf<AttestationResult.Error>()
                                    .cause.shouldBeInstanceOf<AttestationException.Certificate.Time>()

                                val dbg = attestationService.collectDebugInfo(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).serializeCompact()
                                val replayGenericAttestation =
                                    WardenDebugAttestationStatement.deserializeCompact(dbg)
                                        .replayGenericAttestation(ignoreProxy = false)
                                replayGenericAttestation shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                    .replaySmart(ignoreProxy = false)
                                replayGenericAttestation
                                    .shouldBeInstanceOf<AttestationResult.Error>()
                                    .cause.shouldBeInstanceOf<AttestationException.Certificate.Time>()

                            }

                            "too late" {
                                val attestationService = attestationService(
                                    iosBundleIdentifier = recordedAttestation.packageOverride
                                        ?: DEFAULT_IOS_ATTESTATION_CFG.applications.first().bundleIdentifier,
                                    iosSandbox = !(recordedAttestation.isProductionOverride
                                        ?: !DEFAULT_IOS_ATTESTATION_CFG.applications.first().sandbox),
                                    unlockedBootloaderAllowed = false,
                                    timeSource = FixedTimeClock(
                                        recordedAttestation.verificationDate.toInstant()
                                            .toKotlinInstant() + 3000.days
                                    ),
                                )
                                attestationService.verifyAttestation(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).shouldBeInstanceOf<AttestationResult.Error>()
                                    .cause.shouldBeInstanceOf<AttestationException.Certificate.Time>()

                                val dbg = attestationService.collectDebugInfo(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).serializeCompact()
                                val replayGenericAttestation =
                                    WardenDebugAttestationStatement.deserializeCompact(dbg)
                                        .replayGenericAttestation(ignoreProxy = false)
                                replayGenericAttestation shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                    .replaySmart(ignoreProxy = false)
                                replayGenericAttestation
                                    .shouldBeInstanceOf<AttestationResult.Error>()
                                    .cause.shouldBeInstanceOf<AttestationException.Certificate.Time>()

                            }
                        }

                        "package name / bundle identifier" {
                            val attestationService = attestationService(
                                iosSandbox = !(recordedAttestation.isProductionOverride
                                    ?: !DEFAULT_IOS_ATTESTATION_CFG.applications.first().sandbox),
                                androidPackageName = "org.wrong.package.name",
                                iosBundleIdentifier = "org.wrong.bundle.identifier",
                                timeSource = FixedTimeClock(
                                    recordedAttestation.verificationDate.toInstant()
                                        .toKotlinInstant()
                                ),
                            )
                            attestationService.verifyAttestation(
                                recordedAttestation.attestationProof,
                                recordedAttestation.challenge
                            ).shouldBeInstanceOf<AttestationResult.Error>().apply {
                                cause.shouldBeInstanceOf<AttestationException.Content>().also {
                                    when (it.platform) {
                                        Platform.IOS -> it.platformSpecificCause.shouldBeInstanceOf<IosAttestationException>().reason shouldBe IosAttestationException.Reason.IDENTIFIER
                                        Platform.ANDROID -> it.platformSpecificCause.shouldBeInstanceOf<AttestationValueException>().reason shouldBe AttestationValueException.Reason.PACKAGE_NAME
                                        else -> {/*irrelevant*/
                                        }
                                    }
                                }
                            }

                            val dbg = attestationService.collectDebugInfo(
                                recordedAttestation.attestationProof,
                                recordedAttestation.challenge
                            ).serializeCompact()
                            val replayGenericAttestation =
                                WardenDebugAttestationStatement.deserializeCompact(dbg)
                                    .replayGenericAttestation(ignoreProxy = false)
                            replayGenericAttestation shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                .replaySmart(ignoreProxy = false)
                            replayGenericAttestation
                                .shouldBeInstanceOf<AttestationResult.Error>().apply {
                                    cause.shouldBeInstanceOf<AttestationException.Content>().also {
                                        when (it.platform) {
                                            Platform.IOS -> it.platformSpecificCause.shouldBeInstanceOf<IosAttestationException>().reason shouldBe IosAttestationException.Reason.IDENTIFIER
                                            Platform.ANDROID -> it.platformSpecificCause.shouldBeInstanceOf<AttestationValueException>().reason shouldBe AttestationValueException.Reason.PACKAGE_NAME
                                            else -> {/*irrelevant*/
                                            }
                                        }
                                    }
                                }

                        }

                        "challenge" {
                            val attestationService = attestationService(
                                iosBundleIdentifier = recordedAttestation.packageOverride
                                    ?: DEFAULT_IOS_ATTESTATION_CFG.applications.first().bundleIdentifier,
                                iosSandbox = !(recordedAttestation.isProductionOverride
                                    ?: !DEFAULT_IOS_ATTESTATION_CFG.applications.first().sandbox),
                                timeSource = FixedTimeClock(
                                    recordedAttestation.verificationDate.toInstant().toKotlinInstant()
                                ),
                            )
                            attestationService.verifyAttestation(
                                recordedAttestation.attestationProof,
                                recordedAttestation.challenge.reversedArray()
                            ).shouldBeInstanceOf<AttestationResult.Error>().apply {
                                cause.shouldBeInstanceOf<AttestationException.Content>().also {
                                    when (it.platform) {
                                        Platform.IOS -> it.platformSpecificCause.shouldBeInstanceOf<IosAttestationException>().reason shouldBe IosAttestationException.Reason.CHALLENGE
                                        Platform.ANDROID -> it.platformSpecificCause.shouldBeInstanceOf<AttestationValueException>().reason shouldBe AttestationValueException.Reason.CHALLENGE
                                        else -> {/*irrelevant*/
                                        }
                                    }
                                }
                            }
                            val dbg = attestationService.collectDebugInfo(
                                recordedAttestation.attestationProof,
                                recordedAttestation.challenge.reversedArray()
                            ).serializeCompact()
                            val replayGenericAttestation =
                                WardenDebugAttestationStatement.deserializeCompact(dbg)
                                    .replayGenericAttestation(ignoreProxy = false)
                            replayGenericAttestation shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                .replaySmart(ignoreProxy = false)
                            replayGenericAttestation
                                .shouldBeInstanceOf<AttestationResult.Error>().apply {
                                    cause.shouldBeInstanceOf<AttestationException.Content>().also {
                                        when (it.platform) {
                                            Platform.IOS -> it.platformSpecificCause.shouldBeInstanceOf<IosAttestationException>().reason shouldBe IosAttestationException.Reason.CHALLENGE
                                            Platform.ANDROID -> it.platformSpecificCause.shouldBeInstanceOf<AttestationValueException>().reason shouldBe AttestationValueException.Reason.CHALLENGE
                                            else -> {/*irrelevant*/
                                            }
                                        }
                                    }
                                }
                        }

                        "OS Version" {
                            val attestationService = attestationService(
                                iosBundleIdentifier = recordedAttestation.packageOverride
                                    ?: DEFAULT_IOS_ATTESTATION_CFG.applications.first().bundleIdentifier,
                                iosSandbox = !(recordedAttestation.isProductionOverride
                                    ?: !DEFAULT_IOS_ATTESTATION_CFG.applications.first().sandbox),
                                androidVersion = 200000,
                                iosVersion = IOSAttestationConfiguration.OsVersions(
                                    semVer = "99.0",
                                    buildNumber = "999ZZ0"
                                ),
                                timeSource = FixedTimeClock(
                                    recordedAttestation.verificationDate.toInstant()
                                        .toKotlinInstant()
                                ),
                            )
                            attestationService.verifyAttestation(
                                recordedAttestation.attestationProof,
                                recordedAttestation.challenge
                            ).apply {
                                shouldBeInstanceOf<AttestationResult.Error>().apply {
                                    cause.shouldBeInstanceOf<AttestationException.Content>().also {
                                        when (it.platform) {
                                            Platform.IOS -> it.platformSpecificCause.shouldBeInstanceOf<IosAttestationException>().reason shouldBe IosAttestationException.Reason.OS_VERSION
                                            Platform.ANDROID -> it.platformSpecificCause.shouldBeInstanceOf<AttestationValueException>().reason shouldBe AttestationValueException.Reason.OS_VERSION
                                            else -> {/*irrelevant*/
                                            }
                                        }
                                    }
                                }
                            }
                            val dbg = attestationService.collectDebugInfo(
                                recordedAttestation.attestationProof,
                                recordedAttestation.challenge
                            ).serializeCompact()
                            WardenDebugAttestationStatement.deserializeCompact(dbg)
                                .replayGenericAttestation(ignoreProxy = false).apply {
                                this shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                    .replaySmart(ignoreProxy = false)
                                shouldBeInstanceOf<AttestationResult.Error>().apply {
                                    cause.shouldBeInstanceOf<AttestationException.Content>().also {
                                        when (it.platform) {
                                            Platform.IOS -> it.platformSpecificCause.shouldBeInstanceOf<IosAttestationException>().reason shouldBe IosAttestationException.Reason.OS_VERSION
                                            Platform.ANDROID -> it.platformSpecificCause.shouldBeInstanceOf<AttestationValueException>().reason shouldBe AttestationValueException.Reason.OS_VERSION
                                            else -> {/*irrelevant*/
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        "Key Attestation PubKey Mismatch" {
                            val attestationService = attestationService(
                                iosBundleIdentifier = recordedAttestation.packageOverride
                                    ?: DEFAULT_IOS_ATTESTATION_CFG.applications.first().bundleIdentifier,
                                iosSandbox = !(recordedAttestation.isProductionOverride
                                    ?: !DEFAULT_IOS_ATTESTATION_CFG.applications.first().sandbox),
                                timeSource = FixedTimeClock(
                                    recordedAttestation.verificationDate.toInstant()
                                        .toKotlinInstant()
                                ),
                            )
                            val keyToBeAttested = KeyPairGenerator.getInstance("EC")
                                .apply {
                                    initialize(ECGenParameterSpec("secp256r1"))
                                }.genKeyPair().public
                            attestationService.verifyKeyAttestation(
                                recordedAttestation.attestationProof,
                                recordedAttestation.challenge,
                                keyToBeAttested
                            ).apply {
                                isSuccess.shouldBeFalse()
                                details.shouldBeInstanceOf<AttestationResult.Error>().also { println(it) }.apply {
                                    cause.shouldBeInstanceOf<AttestationException.Content>().also {
                                        when (it.platform) {
                                            Platform.IOS -> it.platformSpecificCause.shouldBeInstanceOf<IosAttestationException>().reason shouldBe IosAttestationException.Reason.APP_UNEXPECTED
                                            Platform.ANDROID -> it.platformSpecificCause.shouldBeInstanceOf<AttestationValueException>().reason shouldBe AttestationValueException.Reason.APP_UNEXPECTED
                                            else -> {/*irrelevant*/
                                            }
                                        }
                                    }
                                }
                            }
                            val dbg = attestationService.collectDebugInfo(
                                recordedAttestation.attestationProof,
                                recordedAttestation.challenge,
                                keyToBeAttested
                            ).serializeCompact()
                            WardenDebugAttestationStatement.deserializeCompact(dbg)
                                .replayKeyAttestationLegacy(ignoreProxy = false).apply {
                                this shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                    .replaySmart(ignoreProxy = false)
                                isSuccess.shouldBeFalse()
                                details.shouldBeInstanceOf<AttestationResult.Error>().also { println(it) }.apply {
                                    cause.shouldBeInstanceOf<AttestationException.Content>().also {
                                        when (it.platform) {
                                            Platform.IOS -> it.platformSpecificCause.shouldBeInstanceOf<IosAttestationException>().reason shouldBe IosAttestationException.Reason.APP_UNEXPECTED
                                            Platform.ANDROID -> it.platformSpecificCause.shouldBeInstanceOf<AttestationValueException>().reason shouldBe AttestationValueException.Reason.APP_UNEXPECTED
                                            else -> {/*irrelevant*/
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            "iOS Specific" - {
                iosGood.forEach { recordedAttestation ->
                    recordedAttestation.name - {
                        "OK" - {
                            withData("14", "15.0.1", "16", "16.0.2", "16.2", "16.2.0") { version ->
                                val attestationService = attestationService(
                                    iosVersion = IOSAttestationConfiguration.OsVersions(
                                        semVer = version,
                                        buildNumber = "21A36"
                                    ),
                                    iosBundleIdentifier = recordedAttestation.packageOverride
                                        ?: DEFAULT_IOS_ATTESTATION_CFG.applications.first().bundleIdentifier,
                                    iosSandbox = !(recordedAttestation.isProductionOverride
                                        ?: !DEFAULT_IOS_ATTESTATION_CFG.applications.first().sandbox),
                                    timeSource = FixedTimeClock(
                                        recordedAttestation.verificationDate.toInstant()
                                            .toKotlinInstant()
                                    ),
                                )
                                attestationService.verifyAttestation(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).apply {
                                    also { println(it) }
                                    shouldBeInstanceOf<AttestationResult.IOS>()
                                }

                                val dbg = attestationService.collectDebugInfo(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge,
                                ).serializeCompact()
                                WardenDebugAttestationStatement.deserializeCompact(dbg)
                                    .replayGenericAttestation(ignoreProxy = false).apply {
                                    this shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                        .replaySmart(ignoreProxy = false)
                                    shouldBeInstanceOf<AttestationResult.IOS>()
                                }
                            }
                        }

                        "Fail" - {

                            "borked team identifier" {
                                val attestationService = attestationService(
                                    iosTeamIdentifier = "1234567890",
                                    timeSource = FixedTimeClock(
                                        recordedAttestation.verificationDate.toInstant()
                                            .toKotlinInstant()
                                    ),
                                )
                                attestationService.verifyAttestation(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).apply {
                                    shouldBeInstanceOf<AttestationResult.Error>()
                                        .cause.shouldBeInstanceOf<AttestationException.Content>()
                                        .platformSpecificCause.shouldBeInstanceOf<IosAttestationException>()
                                        .reason shouldBe IosAttestationException.Reason.IDENTIFIER
                                }
                                val dbg = attestationService.collectDebugInfo(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge,
                                ).serializeCompact()
                                WardenDebugAttestationStatement.deserializeCompact(dbg)
                                    .replayGenericAttestation(ignoreProxy = false).apply {
                                    this shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                        .replaySmart(ignoreProxy = false)
                                    shouldBeInstanceOf<AttestationResult.Error>()
                                        .cause.shouldBeInstanceOf<AttestationException.Content>()
                                        .platformSpecificCause.shouldBeInstanceOf<IosAttestationException>()
                                        .reason shouldBe IosAttestationException.Reason.IDENTIFIER
                                }
                            }
                        }
                    }
                }
            }



            "Android Specific" - {
                androidGood.forEach { recordedAttestation ->
                    recordedAttestation.name - {
                        "OK" - {
                            "no patch level" {
                                val attestationService = attestationService(
                                    androidPatchLevel = null,
                                    timeSource = FixedTimeClock(
                                        recordedAttestation.verificationDate.toInstant().toKotlinInstant()
                                    ),
                                )
                                attestationService.verifyAttestation(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).shouldBeInstanceOf<AttestationResult.Android>()
                                val dbg = attestationService.collectDebugInfo(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge,
                                ).serializeCompact()
                                WardenDebugAttestationStatement.deserializeCompact(dbg)
                                    .replayGenericAttestation(ignoreProxy = false).apply {
                                    this shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                        .replaySmart(ignoreProxy = false)
                                    shouldBeInstanceOf<AttestationResult.Android>()
                                }
                            }

                            "enforce locked bootloader" {
                                val attestationService = attestationService(
                                    unlockedBootloaderAllowed = false,
                                    timeSource = FixedTimeClock(
                                        recordedAttestation.verificationDate.toInstant().toKotlinInstant()
                                    ),
                                )
                                attestationService.verifyAttestation(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).shouldBeInstanceOf<AttestationResult.Android>()
                                val dbg = attestationService.collectDebugInfo(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge,
                                ).serializeCompact()
                                WardenDebugAttestationStatement.deserializeCompact(dbg)
                                    .replayGenericAttestation(ignoreProxy = false).apply {
                                    this shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                        .replaySmart(ignoreProxy = false)
                                    shouldBeInstanceOf<AttestationResult.Android>()
                                }
                            }

                            "allow unlocked bootloader" {
                                val attestationService = attestationService(
                                    unlockedBootloaderAllowed = true,
                                    timeSource = FixedTimeClock(
                                        recordedAttestation.verificationDate.toInstant().toKotlinInstant()
                                    ),
                                )
                                attestationService.verifyAttestation(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).shouldBeInstanceOf<AttestationResult.Android>()
                                val dbg = attestationService.collectDebugInfo(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge,
                                ).serializeCompact()
                                WardenDebugAttestationStatement.deserializeCompact(dbg)
                                    .replayGenericAttestation(ignoreProxy = false).apply {
                                    this shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                        .replaySmart(ignoreProxy = false)
                                    shouldBeInstanceOf<AttestationResult.Android>()
                                }
                            }
                        }


                        "Wrongfully disabled HW attestation" - {
                            val clock =
                                FixedTimeClock(recordedAttestation.verificationDate.toInstant().toKotlinInstant())
                            "Software-Only" {
                                Warden(
                                    androidAttestationConfiguration = AndroidAttestationConfiguration(
                                        listOf(
                                            AndroidAttestationConfiguration.AppData(
                                                ANDROID_PACKAGE_NAME,
                                                ANDROID_SIGNATURE_DIGESTS
                                            )
                                        ),
                                        disableHardwareAttestation = true,
                                        enableSoftwareAttestation = true,
                                        ignoreLeafValidity = true
                                    ),
                                    DEFAULT_IOS_ATTESTATION_CFG,
                                    clock = clock
                                ).apply {
                                    verifyAttestation(
                                        recordedAttestation.attestationProof,
                                        recordedAttestation.challenge
                                    ).shouldBeInstanceOf<AttestationResult.Error>()
                                        .cause.shouldBeInstanceOf<AttestationException.Certificate.Trust>()

                                    val dbg = collectDebugInfo(
                                        recordedAttestation.attestationProof,
                                        recordedAttestation.challenge,
                                    ).serializeCompact()
                                    WardenDebugAttestationStatement.deserializeCompact(dbg)
                                        .replayGenericAttestation(ignoreProxy = false).apply {
                                        this shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                            .replaySmart(ignoreProxy = false)
                                        shouldBeInstanceOf<AttestationResult.Error>()
                                            .cause.shouldBeInstanceOf<AttestationException.Certificate.Trust>()
                                    }
                                }
                            }

                            "Nougat attestation" {
                                Warden(
                                    androidAttestationConfiguration = AndroidAttestationConfiguration(
                                        listOf(
                                            AndroidAttestationConfiguration.AppData(
                                                ANDROID_PACKAGE_NAME,
                                                ANDROID_SIGNATURE_DIGESTS
                                            )
                                        ),
                                        disableHardwareAttestation = true,
                                        enableNougatAttestation = true,
                                        ignoreLeafValidity = true
                                    ),
                                    DEFAULT_IOS_ATTESTATION_CFG,
                                    clock = clock
                                ).apply {
                                    verifyAttestation(
                                        recordedAttestation.attestationProof,
                                        recordedAttestation.challenge
                                    ).shouldBeInstanceOf<AttestationResult.Error>()
                                        .cause.shouldBeInstanceOf<AttestationException.Certificate.Trust>()

                                    val dbg = collectDebugInfo(
                                        recordedAttestation.attestationProof,
                                        recordedAttestation.challenge,
                                    ).serializeCompact()
                                    WardenDebugAttestationStatement.deserializeCompact(dbg)
                                        .replayGenericAttestation(ignoreProxy = false).apply {
                                        this shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                            .replaySmart(ignoreProxy = false)
                                        shouldBeInstanceOf<AttestationResult.Error>()
                                            .cause.shouldBeInstanceOf<AttestationException.Certificate.Trust>()
                                    }
                                }
                            }
                            "Software + Nougat attestation" {
                                Warden(
                                    androidAttestationConfiguration = AndroidAttestationConfiguration(
                                        listOf(
                                            AndroidAttestationConfiguration.AppData(
                                                ANDROID_PACKAGE_NAME,
                                                ANDROID_SIGNATURE_DIGESTS
                                            )
                                        ),
                                        disableHardwareAttestation = true,
                                        enableNougatAttestation = true,
                                        enableSoftwareAttestation = true,
                                        ignoreLeafValidity = true
                                    ),
                                    DEFAULT_IOS_ATTESTATION_CFG,
                                    clock = clock
                                ).apply {
                                    verifyAttestation(
                                        recordedAttestation.attestationProof,
                                        recordedAttestation.challenge
                                    ).shouldBeInstanceOf<AttestationResult.Error>().also { println(it) }
                                        .cause.shouldBeInstanceOf<AttestationException.Certificate.Trust>()

                                    val dbg = collectDebugInfo(
                                        recordedAttestation.attestationProof,
                                        recordedAttestation.challenge,
                                    ).serializeCompact()
                                    WardenDebugAttestationStatement.deserializeCompact(dbg)
                                        .replayGenericAttestation(ignoreProxy = false).apply {
                                        this shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                            .replaySmart(ignoreProxy = false)
                                        shouldBeInstanceOf<AttestationResult.Error>()
                                            .cause.shouldBeInstanceOf<AttestationException.Certificate.Trust>()
                                    }
                                }
                            }
                        }

                        "Fail" - {
                            "borked cert chain" - {
                                withData(
                                    listOf(0, 0, 0),
                                    listOf(0, 1, 0),
                                    listOf(0, 2, 1)

                                ) {
                                    val chain = recordedAttestation.attestationProof.slice(it)
                                    attestationService(
                                        unlockedBootloaderAllowed = false,
                                        timeSource = FixedTimeClock(
                                            recordedAttestation.verificationDate.toInstant().toKotlinInstant()
                                        ),
                                    ).apply {
                                        val dbg = collectDebugInfo(
                                            chain,
                                            recordedAttestation.challenge,
                                        ).serializeCompact()
                                        WardenDebugAttestationStatement.deserializeCompact(dbg)
                                            .replayGenericAttestation(ignoreProxy = false)
                                            .apply {
                                                this shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                                    .replaySmart(ignoreProxy = false)
                                                shouldBeInstanceOf<AttestationResult.Error>()
                                                    .cause.shouldBeInstanceOf<AttestationException.Certificate.Trust>()
                                            }
                                    }.verifyAttestation(
                                        chain,
                                        recordedAttestation.challenge
                                    ).apply {//makes interactive debugging easier
                                        shouldBeInstanceOf<AttestationResult.Error>()
                                            .cause.shouldBeInstanceOf<AttestationException.Certificate.Trust>()
                                    }

                                    attestationService(
                                        unlockedBootloaderAllowed = false,
                                        timeSource = FixedTimeClock(
                                            recordedAttestation.verificationDate.toInstant().toKotlinInstant()
                                        ),
                                    ).apply {
                                        val dbg = collectDebugInfo(
                                            chain,
                                            recordedAttestation.challenge,
                                        ).serializeCompact()
                                        WardenDebugAttestationStatement.deserializeCompact(dbg)
                                            .replayGenericAttestation(ignoreProxy = false)
                                            .apply {
                                                this shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                                    .replaySmart(ignoreProxy = false)
                                                shouldBeInstanceOf<AttestationResult.Error>()
                                                    .cause.shouldBeInstanceOf<AttestationException.Certificate.Trust>()
                                            }
                                    }.verifyAttestation(
                                        chain,
                                        recordedAttestation.challenge
                                    ).apply {//makes interactive debugging easier
                                        shouldBeInstanceOf<AttestationResult.Error>()
                                            .cause.shouldBeInstanceOf<AttestationException.Certificate.Trust>()
                                    }

                                    attestationService(
                                        unlockedBootloaderAllowed = false,
                                        timeSource = FixedTimeClock(
                                            recordedAttestation.verificationDate.toInstant().toKotlinInstant()
                                        ),
                                    ).apply {
                                        val dbg = collectDebugInfo(
                                            chain,
                                            recordedAttestation.challenge,
                                        ).serializeCompact()
                                        WardenDebugAttestationStatement.deserializeCompact(dbg)
                                            .replayGenericAttestation(ignoreProxy = false)
                                            .apply {
                                                this shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                                    .replaySmart(ignoreProxy = false)
                                                shouldBeInstanceOf<AttestationResult.Error>()
                                                    .cause.shouldBeInstanceOf<AttestationException.Certificate.Trust>()
                                            }
                                    }.verifyAttestation(
                                        chain,
                                        recordedAttestation.challenge
                                    ).apply { //makes interactive debugging easier
                                        shouldBeInstanceOf<AttestationResult.Error>()
                                            .cause.shouldBeInstanceOf<AttestationException.Certificate.Trust>()
                                    }
                                }
                            }

                            "require StrongBox" {
                                attestationService(
                                    requireStrongBox = true,
                                    timeSource = FixedTimeClock(
                                        recordedAttestation.verificationDate.toInstant().toKotlinInstant()
                                    ),
                                ).apply {
                                    val dbg = collectDebugInfo(
                                        recordedAttestation.attestationProof,
                                        recordedAttestation.challenge,
                                    ).serializeCompact()
                                    WardenDebugAttestationStatement.deserializeCompact(dbg)
                                        .replayGenericAttestation(ignoreProxy = false).apply {
                                        this shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                            .replaySmart(ignoreProxy = false)
                                        shouldBeInstanceOf<AttestationResult.Error>()
                                            .cause.shouldBeInstanceOf<AttestationException.Content>()
                                    }
                                }.verifyAttestation(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).shouldBeInstanceOf<AttestationResult.Error>()
                                    .cause.shouldBeInstanceOf<AttestationException.Content>()
                            }

                            "wrong signature digests" {
                                attestationService(
                                    androidAppSignatureDigest = listOf(
                                        byteArrayOf(0, 32, 55, 29, 120, 22, 0),
                                        /*this one's an invalid digest and must not affect the tests*/
                                        "LvfTC77F/uSecSfJDeLdxQ3gZrVLHX8+NNBp7AiUO0E=".decodeBase64ToArray()!!
                                    ),
                                    timeSource = FixedTimeClock(
                                        recordedAttestation.verificationDate.toInstant()
                                            .toKotlinInstant()
                                    ),
                                ).apply {
                                    val dbg = collectDebugInfo(
                                        recordedAttestation.attestationProof,
                                        recordedAttestation.challenge,
                                    ).serializeCompact()
                                    WardenDebugAttestationStatement.deserializeCompact(dbg)
                                        .replayGenericAttestation(ignoreProxy = false).apply {
                                        this shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                            .replaySmart(ignoreProxy = false)
                                        shouldBeInstanceOf<AttestationResult.Error>()
                                            .cause.shouldBeInstanceOf<AttestationException.Content>()
                                    }
                                }.verifyAttestation(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).shouldBeInstanceOf<AttestationResult.Error>()
                                    .cause.shouldBeInstanceOf<AttestationException.Content>()
                            }

                            //just to check whether this propagates
                            "no signature digests, cannot instantiate" {
                                shouldThrow<at.asitplus.attestation.android.exceptions.AndroidAttestationException> {
                                    attestationService(
                                        androidAppSignatureDigest = listOf(),
                                        timeSource = FixedTimeClock(
                                            recordedAttestation.verificationDate.toInstant()
                                                .toKotlinInstant()
                                        ),
                                    )
                                }
                            }

                            "app version" {
                                attestationService(
                                    androidAppVersion = 200000,
                                    timeSource = FixedTimeClock(
                                        recordedAttestation.verificationDate.toInstant()
                                            .toKotlinInstant()
                                    ),
                                ).apply {
                                    val dbg = collectDebugInfo(
                                        recordedAttestation.attestationProof,
                                        recordedAttestation.challenge,
                                    ).serializeCompact()
                                    WardenDebugAttestationStatement.deserializeCompact(dbg)
                                        .replayGenericAttestation(ignoreProxy = false).apply {
                                        this shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                            .replaySmart(ignoreProxy = false)
                                        shouldBeInstanceOf<AttestationResult.Error>()
                                            .cause.shouldBeInstanceOf<AttestationException.Content>()
                                    }
                                }.verifyAttestation(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).shouldBeInstanceOf<AttestationResult.Error>()
                                    .cause.shouldBeInstanceOf<AttestationException.Content>()

                            }

                            "patch level" {
                                attestationService(
                                    androidPatchLevel = PatchLevel(2030, 1),
                                    timeSource = FixedTimeClock(
                                        recordedAttestation.verificationDate.toInstant()
                                            .toKotlinInstant()
                                    ),
                                ).apply {
                                    val dbg = collectDebugInfo(
                                        recordedAttestation.attestationProof,
                                        recordedAttestation.challenge,
                                    ).serializeCompact()
                                    WardenDebugAttestationStatement.deserializeCompact(dbg)
                                        .replayGenericAttestation(ignoreProxy = false).apply {
                                        this shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                            .replaySmart(ignoreProxy = false)
                                        shouldBeInstanceOf<AttestationResult.Error>()
                                            .cause.shouldBeInstanceOf<AttestationException.Content>()
                                    }
                                }.verifyAttestation(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).shouldBeInstanceOf<AttestationResult.Error>()
                                    .cause.shouldBeInstanceOf<AttestationException.Content>()
                            }

                            "rollback resistance" {
                                attestationService(
                                    requireRollbackResistance = true,
                                    timeSource = FixedTimeClock(
                                        recordedAttestation.verificationDate.toInstant()
                                            .toKotlinInstant()
                                    ),
                                ).apply {
                                    val dbg = collectDebugInfo(
                                        recordedAttestation.attestationProof,
                                        recordedAttestation.challenge,
                                    ).serializeCompact()
                                    WardenDebugAttestationStatement.deserializeCompact(dbg)
                                        .replayGenericAttestation(ignoreProxy = false).apply {
                                        this shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                            .replaySmart(ignoreProxy = false)
                                        shouldBeInstanceOf<AttestationResult.Error>()
                                            .cause.shouldBeInstanceOf<AttestationException.Content>()
                                    }
                                }.verifyAttestation(
                                    recordedAttestation.attestationProof,
                                    recordedAttestation.challenge
                                ).shouldBeInstanceOf<AttestationResult.Error>()
                                    .cause.shouldBeInstanceOf<AttestationException.Content>()
                            }
                        }
                    }
                }
            }
        }

        "The Bad" - {
            "Software-Only Keystore" - {
                AttestationData(
                    "Android Emulator",
                    challengeB64 = "RN9CjU7I5zpvCh7D3vi/aA==",
                    attestationProofB64 = listOf(
                        """MIIC+jCCAqCgAwIBAgIBATAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCVVMxEzARBgNVB
                    AgMCkNhbGlmb3JuaWExFTATBgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZ
                    DE7MDkGA1UEAwwyQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBJbnRlc
                    m1lZGlhdGUwHhcNNzAwMTAxMDAwMDAwWhcNNjkxMjMxMjM1OTU5WjAfMR0wGwYDVQQDDBRBb
                    mRyb2lkIEtleXN0b3JlIEtleTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIEAthaOZ2+nZ
                    ZyYdoeLYNL5yZozzfMdrfrZcG2RI1juriVparubkzxZGCs4KcReh1aDhWFsDxQWYAeJLcFN8
                    rOjggFhMIIBXTALBgNVHQ8EBAMCB4AwggErBgorBgEEAdZ5AgERBIIBGzCCARcCAQQKAQACA
                    SkKAQAEEETfQo1OyOc6bwoew974v2gEADCB8qEIMQYCAQICAQOiAwIBA6MEAgIBAKUIMQYCA
                    QICAQSqAwIBAb+DdwIFAL+FPQgCBgGHj7zJmL+FPgMCAQC/hUBMMEoEIAAAAAAAAAAAAAAAA
                    AAAAAAAAAAAAAAAAAAAAAAAAAAAAQEACgECBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                    AAAAAAAAL+FQQUCAwGtsL+FQgUCAwMVG7+FRU8ETTBLMSUwIwQeYXQuYXNpdHBsdXMuYXR0Z
                    XN0YXRpb25fY2xpZW50AgEBMSIEIDS5dixNbJDUhDGUDFe95zFCWLJkIO/hasf3J08NMwrVM
                    AAwHwYDVR0jBBgwFoAUP/ys1hqxOp6BILjVJRzFZbsekakwCgYIKoZIzj0EAwIDSAAwRQIgW
                    CsSigJsOLe9hli462AL/TuPqLuuIKelSVEe/PsnrWUCIQC+JExSC5l3slEBhDKxMD3otjwr0
                    DK0Jav50CzyK80ILg==
                    """,
                        """MIICeDCCAh6gAwIBAgICEAEwCgYIKoZIzj0EAwIwgZgxCzAJBgNVBAYTAlVTMRMwEQYDV
                    QQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRUwEwYDVQQKDAxHb29nb
                    GUsIEluYy4xEDAOBgNVBAsMB0FuZHJvaWQxMzAxBgNVBAMMKkFuZHJvaWQgS2V5c3RvcmUgU
                    29mdHdhcmUgQXR0ZXN0YXRpb24gUm9vdDAeFw0xNjAxMTEwMDQ2MDlaFw0yNjAxMDgwMDQ2M
                    DlaMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMR29vZ
                    2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTswOQYDVQQDDDJBbmRyb2lkIEtleXN0b3JlI
                    FNvZnR3YXJlIEF0dGVzdGF0aW9uIEludGVybWVkaWF0ZTBZMBMGByqGSM49AgEGCCqGSM49A
                    wEHA0IABOueefhCY1msyyqRTImGzHCtkGaTgqlzJhP+rMv4ISdMIXSXSir+pblNf2bU4GUQZ
                    jW8U7ego6ZxWD7bPhGuEBSjZjBkMB0GA1UdDgQWBBQ//KzWGrE6noEguNUlHMVlux6RqTAfB
                    gNVHSMEGDAWgBTIrel3TEXDo88NFhDkeUM6IVowzzASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA
                    1UdDwEB/wQEAwIChDAKBggqhkjOPQQDAgNIADBFAiBLipt77oK8wDOHri/AiZi03cONqycqR
                    Z9pDMfDktQPjgIhAO7aAV229DLp1IQ7YkyUBO86fMy9Xvsiu+f+uXc/WT/7
                    """,
                        """MIICizCCAjKgAwIBAgIJAKIFntEOQ1tXMAoGCCqGSM49BAMCMIGYMQswCQYDVQQGEwJVU
                    zETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzEVMBMGA1UEC
                    gwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTMwMQYDVQQDDCpBbmRyb2lkIEtle
                    XN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIFJvb3QwHhcNMTYwMTExMDA0MzUwWhcNMzYwM
                    TA2MDA0MzUwWjCBmDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVB
                    AcMDU1vdW50YWluIFZpZXcxFTATBgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kc
                    m9pZDEzMDEGA1UEAwwqQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb
                    290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamguD/9/S
                    Q59dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpKNjMGEwHQYDVR0OBBYEF
                    Mit6XdMRcOjzw0WEOR5QzohWjDPMB8GA1UdIwQYMBaAFMit6XdMRcOjzw0WEOR5QzohWjDPM
                    A8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgKEMAoGCCqGSM49BAMCA0cAMEQCIDUho
                    ++LNEYenNVg8x1YiSBq3KNlQfYNns6KGYxmSGB7AiBNC/NR2TB8fVvaNTQdqEcbY6WFZTytT
                    ySn502vQX3xvw==
                    """
                    ),
                    isoDate = "2023-04-17T15:10:00Z",
                    pubKeyB64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgQC2Fo5nb6dlnJh2h4tg0vnJmjPN8x2t+tlwbZEjWO6uJWlqu5uTPFkYKzgpxF6HVoOFYWwPFBZgB4ktwU3ysw=="
                ).apply {

                    val clock = FixedTimeClock(verificationDate.toInstant().toKotlinInstant())
                    "HW Attestation should fail" {
                        attestationService(
                            timeSource = clock,
                        ).apply {
                            val dbg = collectDebugInfo(
                                attestationProof,
                                challenge,
                            ).serializeCompact()
                            WardenDebugAttestationStatement.deserializeCompact(dbg)
                                .replayGenericAttestation(ignoreProxy = false).apply {
                                this shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                    .replaySmart(ignoreProxy = false)
                                shouldBeInstanceOf<AttestationResult.Error>()
                                    .cause.shouldBeInstanceOf<AttestationException.Certificate.Trust>()
                            }
                        }.verifyAttestation(
                            attestationProof,
                            challenge
                        ).shouldBeInstanceOf<AttestationResult.Error>()
                            .cause.shouldBeInstanceOf<AttestationException.Certificate.Trust>()
                    }

                    "Nougat Hybrid attestation should fail" {
                        Warden(
                            androidAttestationConfiguration = AndroidAttestationConfiguration(
                                listOf(
                                    AndroidAttestationConfiguration.AppData(
                                        ANDROID_PACKAGE_NAME,
                                        ANDROID_SIGNATURE_DIGESTS
                                    )
                                ),
                                disableHardwareAttestation = true,
                                enableNougatAttestation = true,
                                ignoreLeafValidity = true
                            ),
                            DEFAULT_IOS_ATTESTATION_CFG,
                            clock = clock
                        ).apply {
                            verifyAttestation(
                                attestationProof,
                                challenge
                            ).shouldBeInstanceOf<AttestationResult.Error>()
                                .cause.shouldBeInstanceOf<AttestationException.Content>()

                            val dbg = collectDebugInfo(
                                attestationProof,
                                challenge,
                            ).serializeCompact()
                            WardenDebugAttestationStatement.deserializeCompact(dbg)
                                .replayGenericAttestation(ignoreProxy = false).apply {
                                this shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                    .replaySmart(ignoreProxy = false)
                                shouldBeInstanceOf<AttestationResult.Error>()
                                    .cause.shouldBeInstanceOf<AttestationException.Content>()
                            }
                        }
                    }

                    "HW Attestation and Nougat Hybrid attestation combined should fail" {
                        Warden(
                            androidAttestationConfiguration = AndroidAttestationConfiguration(
                                listOf(
                                    AndroidAttestationConfiguration.AppData(
                                        ANDROID_PACKAGE_NAME,
                                        ANDROID_SIGNATURE_DIGESTS
                                    )
                                ),
                                enableNougatAttestation = true,
                                ignoreLeafValidity = true
                            ),
                            DEFAULT_IOS_ATTESTATION_CFG,
                            clock = clock
                        ).apply {
                            verifyAttestation(
                                attestationProof,
                                challenge
                            ).shouldBeInstanceOf<AttestationResult.Error>()
                                .cause.shouldBeInstanceOf<AttestationException.Content>()
                            val dbg = collectDebugInfo(
                                attestationProof,
                                challenge,
                            ).serializeCompact()
                            WardenDebugAttestationStatement.deserializeCompact(dbg)
                                .replayGenericAttestation(ignoreProxy = false).apply {
                                this shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                    .replaySmart(ignoreProxy = false)
                                shouldBeInstanceOf<AttestationResult.Error>()
                                    .cause.shouldBeInstanceOf<AttestationException.Content>()
                            }
                        }
                    }

                    "Software attestation should work" - {

                        "stand-alone" {
                            Warden(
                                androidAttestationConfiguration = AndroidAttestationConfiguration(
                                    listOf(
                                        AndroidAttestationConfiguration.AppData(
                                            ANDROID_PACKAGE_NAME,
                                            ANDROID_SIGNATURE_DIGESTS
                                        )
                                    ),
                                    disableHardwareAttestation = true,
                                    enableSoftwareAttestation = true,
                                    ignoreLeafValidity = true,
                                    attestationStatementValiditySeconds = 10 * 60
                                ),
                                DEFAULT_IOS_ATTESTATION_CFG,
                                clock = clock
                            ).apply {
                                verifyAttestation(
                                    attestationProof,
                                    challenge
                                ).shouldBeInstanceOf<AttestationResult.Android>().attestationRecord
                                val dbg = collectDebugInfo(
                                    attestationProof,
                                    challenge,
                                ).serializeCompact()
                                val replayGenericAttestation =
                                    WardenDebugAttestationStatement.deserializeCompact(dbg)
                                        .replayGenericAttestation(ignoreProxy = false)
                                replayGenericAttestation shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                    .replaySmart(ignoreProxy = false)
                                replayGenericAttestation
                                    .shouldBeInstanceOf<AttestationResult.Android>()
                            }
                        }

                        "with Nougat attestation" {
                            Warden(
                                androidAttestationConfiguration = AndroidAttestationConfiguration(
                                    listOf(
                                        AndroidAttestationConfiguration.AppData(
                                            ANDROID_PACKAGE_NAME,
                                            ANDROID_SIGNATURE_DIGESTS
                                        )
                                    ),
                                    disableHardwareAttestation = true,
                                    enableNougatAttestation = true,
                                    enableSoftwareAttestation = true,
                                    ignoreLeafValidity = true,
                                    attestationStatementValiditySeconds = 10 * 60
                                ),
                                DEFAULT_IOS_ATTESTATION_CFG,
                                clock = clock
                            ).apply {
                                verifyAttestation(
                                    attestationProof,
                                    challenge
                                ).shouldBeInstanceOf<AttestationResult.Android>().attestationRecord
                                val dbg = collectDebugInfo(
                                    attestationProof,
                                    challenge,
                                ).serializeCompact()
                                val replayGenericAttestation =
                                    WardenDebugAttestationStatement.deserializeCompact(dbg)
                                        .replayGenericAttestation(ignoreProxy = false)
                                replayGenericAttestation shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                    .replaySmart(ignoreProxy = false)
                                replayGenericAttestation
                                    .shouldBeInstanceOf<AttestationResult.Android>()
                            }
                        }

                        "with Nougat and HW attestation" {
                            Warden(
                                androidAttestationConfiguration = AndroidAttestationConfiguration(
                                    listOf(
                                        AndroidAttestationConfiguration.AppData(
                                            ANDROID_PACKAGE_NAME,
                                            ANDROID_SIGNATURE_DIGESTS
                                        )
                                    ),
                                    enableNougatAttestation = true,
                                    enableSoftwareAttestation = true,
                                    ignoreLeafValidity = true,
                                    attestationStatementValiditySeconds = 10 * 60
                                ),
                                DEFAULT_IOS_ATTESTATION_CFG,
                                clock = clock
                            ).apply {
                                verifyAttestation(
                                    attestationProof,
                                    challenge
                                ).shouldBeInstanceOf<AttestationResult.Android>().attestationRecord
                                val dbg = collectDebugInfo(
                                    attestationProof,
                                    challenge,
                                ).serializeCompact()
                                val replayGenericAttestation =
                                    WardenDebugAttestationStatement.deserializeCompact(dbg)
                                        .replayGenericAttestation(ignoreProxy = false)
                                replayGenericAttestation shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                    .replaySmart(ignoreProxy = false)
                                replayGenericAttestation
                                    .shouldBeInstanceOf<AttestationResult.Android>()
                            }
                        }
                    }
                }
            }

            "Nougat to Oreo (LineageOS) bq Aquaris X" - {
                val data = AttestationData(
                    "bq Aquaris X with LineageOS",
                    "foobdar".encodeToByteArray().encodeBase64(),
                    listOf(
                        "MIICkDCCAjagAwIBAgIBATAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFTATBgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDE7MDkGA1UEAwwyQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBJbnRlcm1lZGlhdGUwIBcNNzAwMTAxMDAwMDAwWhgPMjEwNjAyMDcwNjI4MTVaMB8xHTAbBgNVBAMMFEFuZHJvaWQgS2V5c3RvcmUgS2V5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEoX5eWkxsJOk2z6S5tclt6bOyJhS3b+2+ULx3O3zZAwFNrbWP52YnQzp/lsexI99lx/Z5NRzJ9x0aDLdIcR/AyqOB9jCB8zALBgNVHQ8EBAMCB4AwgcIGCisGAQQB1nkCAREEgbMwgbACAQIKAQACAQEKAQEEB2Zvb2JkYXIEADBev4U9BwIFAKtq1Vi/hUVPBE0wSzElMCMEHmNvbS5leGFtcGxlLnRydXN0ZWRhcHBsaWNhdGlvbgIBATEiBCCI5cOT6u82gpgAtB33hqUv8KWCFYUMqKZQc4Wa3PAZDzA3oQgxBgIBAgIBA6IDAgEDowQCAgEApQgxBgIBAAIBBKoDAgEBv4N3AgUAv4U+AwIBAL+FPwIFADAfBgNVHSMEGDAWgBQ//KzWGrE6noEguNUlHMVlux6RqTAKBggqhkjOPQQDAgNIADBFAiBiMBtVeUV4j1VOiRU8DnGzq9/xtHfl0wra1xnsmxG+LAIhAJAroVhVcxxItgYZEMN1AaWqmZUXFtktQeLXh7u2F3d+",
                        "MIICeDCCAh6gAwIBAgICEAEwCgYIKoZIzj0EAwIwgZgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRUwEwYDVQQKDAxHb29nbGUsIEluYy4xEDAOBgNVBAsMB0FuZHJvaWQxMzAxBgNVBAMMKkFuZHJvaWQgS2V5c3RvcmUgU29mdHdhcmUgQXR0ZXN0YXRpb24gUm9vdDAeFw0xNjAxMTEwMDQ2MDlaFw0yNjAxMDgwMDQ2MDlaMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTswOQYDVQQDDDJBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIEludGVybWVkaWF0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOueefhCY1msyyqRTImGzHCtkGaTgqlzJhP+rMv4ISdMIXSXSir+pblNf2bU4GUQZjW8U7ego6ZxWD7bPhGuEBSjZjBkMB0GA1UdDgQWBBQ//KzWGrE6noEguNUlHMVlux6RqTAfBgNVHSMEGDAWgBTIrel3TEXDo88NFhDkeUM6IVowzzASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIChDAKBggqhkjOPQQDAgNIADBFAiBLipt77oK8wDOHri/AiZi03cONqycqRZ9pDMfDktQPjgIhAO7aAV229DLp1IQ7YkyUBO86fMy9Xvsiu+f+uXc/WT/7",
                        "MIICizCCAjKgAwIBAgIJAKIFntEOQ1tXMAoGCCqGSM49BAMCMIGYMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTMwMQYDVQQDDCpBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIFJvb3QwHhcNMTYwMTExMDA0MzUwWhcNMzYwMTA2MDA0MzUwWjCBmDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTATBgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDEzMDEGA1UEAwwqQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamguD/9/SQ59dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpKNjMGEwHQYDVR0OBBYEFMit6XdMRcOjzw0WEOR5QzohWjDPMB8GA1UdIwQYMBaAFMit6XdMRcOjzw0WEOR5QzohWjDPMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgKEMAoGCCqGSM49BAMCA0cAMEQCIDUho++LNEYenNVg8x1YiSBq3KNlQfYNns6KGYxmSGB7AiBNC/NR2TB8fVvaNTQdqEcbY6WFZTytTySn502vQX3xvw=="
                    ),
                    isoDate = "2023-09-10T00:00:00Z"
                )
                val signatureDigests = listOf(
                    "88E5C393EAEF36829800B41DF786A52FF0A58215850CA8A65073859ADCF0190F".hexToByteArray(HexFormat.UpperCase)
                )
                val packageName = "com.example.trustedapplication"

                val clock = FixedTimeClock(data.verificationDate.toInstant().toKotlinInstant())

                "Nougat Hybrid attestation should work" - {
                    "stand-alone" {
                        Warden(
                            androidAttestationConfiguration = AndroidAttestationConfiguration(
                                listOf(
                                    AndroidAttestationConfiguration.AppData(
                                        packageName,
                                        signatureDigests
                                    )
                                ),
                                disableHardwareAttestation = true,
                                enableNougatAttestation = true,
                                ignoreLeafValidity = true
                            ),
                            DEFAULT_IOS_ATTESTATION_CFG,
                            clock = clock
                        ).apply {
                            verifyAttestation(
                                data.attestationProof,
                                data.challenge
                            ).shouldBeInstanceOf<AttestationResult.Android>().attestationRecord.apply {
                                attestationSecurityLevel() shouldBe ParsedAttestationRecord.SecurityLevel.SOFTWARE
                                keymasterSecurityLevel() shouldBe ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT
                            }

                            val dbg = collectDebugInfo(
                                data.attestationProof,
                                data.challenge,
                            ).serializeCompact()
                            val replayGenericAttestation =
                                WardenDebugAttestationStatement.deserializeCompact(dbg)
                                    .replayGenericAttestation(ignoreProxy = false)
                            replayGenericAttestation shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                .replaySmart(ignoreProxy = false)
                            replayGenericAttestation
                                .shouldBeInstanceOf<AttestationResult.Android>().attestationRecord.apply {
                                    attestationSecurityLevel() shouldBe ParsedAttestationRecord.SecurityLevel.SOFTWARE
                                    keymasterSecurityLevel() shouldBe ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT

                                }

                        }
                    }


                    "with Hardware attestation" {
                        Warden(
                            androidAttestationConfiguration = AndroidAttestationConfiguration(
                                listOf(
                                    AndroidAttestationConfiguration.AppData(
                                        packageName,
                                        signatureDigests
                                    )
                                ),
                                enableNougatAttestation = true,
                                ignoreLeafValidity = true
                            ),
                            DEFAULT_IOS_ATTESTATION_CFG,
                            clock = clock
                        ).apply {
                            verifyAttestation(
                                data.attestationProof,
                                data.challenge
                            ).shouldBeInstanceOf<AttestationResult.Android>().attestationRecord.apply {
                                attestationSecurityLevel() shouldBe ParsedAttestationRecord.SecurityLevel.SOFTWARE
                                keymasterSecurityLevel() shouldBe ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT
                            }
                            val dbg = collectDebugInfo(
                                data.attestationProof,
                                data.challenge,
                            ).serializeCompact()
                            val replayGenericAttestation =
                                WardenDebugAttestationStatement.deserializeCompact(dbg)
                                    .replayGenericAttestation(ignoreProxy = false)
                            replayGenericAttestation shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                .replaySmart(ignoreProxy = false)
                            replayGenericAttestation
                                .shouldBeInstanceOf<AttestationResult.Android>().attestationRecord.apply {
                                    attestationSecurityLevel() shouldBe ParsedAttestationRecord.SecurityLevel.SOFTWARE
                                    keymasterSecurityLevel() shouldBe ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT

                                }

                        }
                    }

                    "with Hardware + Sowftware Attestation " {
                        Warden(
                            androidAttestationConfiguration = AndroidAttestationConfiguration(
                                listOf(
                                    AndroidAttestationConfiguration.AppData(
                                        packageName,
                                        signatureDigests
                                    )
                                ),
                                enableSoftwareAttestation = true,
                                enableNougatAttestation = true,
                                ignoreLeafValidity = true
                            ),
                            DEFAULT_IOS_ATTESTATION_CFG,
                            clock = clock
                        ).apply {
                            verifyAttestation(
                                data.attestationProof,
                                data.challenge
                            ).shouldBeInstanceOf<AttestationResult.Android>().attestationRecord.apply {
                                attestationSecurityLevel() shouldBe ParsedAttestationRecord.SecurityLevel.SOFTWARE
                                keymasterSecurityLevel() shouldBe ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT
                            }
                            val dbg = collectDebugInfo(
                                data.attestationProof,
                                data.challenge,
                            ).serializeCompact()
                            val replayGenericAttestation =
                                WardenDebugAttestationStatement.deserializeCompact(dbg)
                                    .replayGenericAttestation(ignoreProxy = false)
                            replayGenericAttestation shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                .replaySmart(ignoreProxy = false)
                            replayGenericAttestation
                                .shouldBeInstanceOf<AttestationResult.Android>().attestationRecord.apply {
                                    attestationSecurityLevel() shouldBe ParsedAttestationRecord.SecurityLevel.SOFTWARE
                                    keymasterSecurityLevel() shouldBe ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT

                                }

                        }
                    }

                    "with Software Attestation" {
                        Warden(
                            androidAttestationConfiguration = AndroidAttestationConfiguration(
                                listOf(
                                    AndroidAttestationConfiguration.AppData(
                                        packageName,
                                        signatureDigests
                                    )
                                ),
                                disableHardwareAttestation = true,
                                enableSoftwareAttestation = true,
                                enableNougatAttestation = true,
                                ignoreLeafValidity = true
                            ),
                            DEFAULT_IOS_ATTESTATION_CFG,
                            clock = clock
                        ).apply {
                            verifyAttestation(
                                data.attestationProof,
                                data.challenge
                            ).shouldBeInstanceOf<AttestationResult.Android>().attestationRecord.apply {
                                attestationSecurityLevel() shouldBe ParsedAttestationRecord.SecurityLevel.SOFTWARE
                                keymasterSecurityLevel() shouldBe ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT
                            }
                            val dbg = collectDebugInfo(
                                data.attestationProof,
                                data.challenge,
                            ).serializeCompact()
                            val replayGenericAttestation =
                                WardenDebugAttestationStatement.deserializeCompact(dbg)
                                    .replayGenericAttestation(ignoreProxy = false)
                            replayGenericAttestation shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                .replaySmart(ignoreProxy = false)
                            replayGenericAttestation
                                .shouldBeInstanceOf<AttestationResult.Android>().attestationRecord.apply {
                                    attestationSecurityLevel() shouldBe ParsedAttestationRecord.SecurityLevel.SOFTWARE
                                    keymasterSecurityLevel() shouldBe ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT

                                }

                        }
                    }
                }

                "Hardware attestation should fail" {
                    Warden(
                        androidAttestationConfiguration = AndroidAttestationConfiguration(
                            listOf(
                                AndroidAttestationConfiguration.AppData(
                                    packageName,
                                    signatureDigests
                                )
                            ),
                            ignoreLeafValidity = true
                        ),
                        DEFAULT_IOS_ATTESTATION_CFG,
                        clock = clock
                    ).apply {
                        verifyAttestation(
                            data.attestationProof,
                            data.challenge
                        ).shouldBeInstanceOf<AttestationResult.Error>()
                            .cause.shouldBeInstanceOf<AttestationException.Certificate.Trust>()

                        val dbg = collectDebugInfo(
                            data.attestationProof,
                            data.challenge,
                        ).serializeCompact()
                        val replayGenericAttestation =
                            WardenDebugAttestationStatement.deserializeCompact(dbg)
                                .replayGenericAttestation(ignoreProxy = false)
                        replayGenericAttestation shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                            .replaySmart(ignoreProxy = false)
                        replayGenericAttestation
                            .shouldBeInstanceOf<AttestationResult.Error>()
                            .cause.shouldBeInstanceOf<AttestationException.Certificate.Trust>()
                    }
                }

                "Hardware + SW attestation should fail" {
                    Warden(
                        androidAttestationConfiguration = AndroidAttestationConfiguration(
                            listOf(
                                AndroidAttestationConfiguration.AppData(
                                    packageName,
                                    signatureDigests
                                )
                            ),
                            enableSoftwareAttestation = true,
                            ignoreLeafValidity = true
                        ),
                        DEFAULT_IOS_ATTESTATION_CFG,
                        clock = clock
                    ).apply {
                        verifyAttestation(
                            data.attestationProof,
                            data.challenge
                        ).shouldBeInstanceOf<AttestationResult.Error>()
                            .cause.shouldBeInstanceOf<AttestationException.Content>()

                        val dbg = collectDebugInfo(
                            data.attestationProof,
                            data.challenge,
                        ).serializeCompact()
                        val replayGenericAttestation =
                            WardenDebugAttestationStatement.deserializeCompact(dbg)
                                .replayGenericAttestation(ignoreProxy = false)
                        replayGenericAttestation shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                            .replaySmart(ignoreProxy = false)
                        replayGenericAttestation
                            .shouldBeInstanceOf<AttestationResult.Error>()
                            .cause.shouldBeInstanceOf<AttestationException.Content>()
                    }
                }

                "SW attestation should fail" {
                    Warden(
                        androidAttestationConfiguration = AndroidAttestationConfiguration(
                            listOf(
                                AndroidAttestationConfiguration.AppData(
                                    packageName,
                                    signatureDigests
                                )
                            ),
                            disableHardwareAttestation = true,
                            enableSoftwareAttestation = true,
                            ignoreLeafValidity = true
                        ),
                        DEFAULT_IOS_ATTESTATION_CFG,
                        clock = clock
                    ).apply {
                        verifyAttestation(
                            data.attestationProof,
                            data.challenge
                        ).shouldBeInstanceOf<AttestationResult.Error>()
                            .cause.shouldBeInstanceOf<AttestationException.Content>()
                        val dbg = collectDebugInfo(
                            data.attestationProof,
                            data.challenge,
                        ).serializeCompact()
                        val replayGenericAttestation =
                            WardenDebugAttestationStatement.deserializeCompact(dbg)
                                .replayGenericAttestation(ignoreProxy = false)
                        replayGenericAttestation shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                            .replaySmart(ignoreProxy = false)
                        replayGenericAttestation
                            .shouldBeInstanceOf<AttestationResult.Error>()
                            .cause.shouldBeInstanceOf<AttestationException.Content>()
                    }
                }
            }

            //TODO bootloader unlocked
            //TODO jailbroken iphone
        }

        "And the Fabulous" - {
            val ios = "D4BD9EFC2A1AB1E2351143A4E67BB91F" to
                    Json.decodeFromStream<Attestation>(WardenTest::class.java.classLoader.getResourceAsStream("ios-appattest.json"))
            val android = "CAC4307080875C418BEB668E825649DC" to
                    Json.decodeFromStream<Attestation>(this::class.java.classLoader.getResourceAsStream("aksattest.json"))

            val androidSigDigests = listOf(
                "941A4513A3027563D3A6EA48EEE85BA45EB9F69CEEA19EF0EBB17F100BFC8878".hexToByteArray(
                    HexFormat.UpperCase
                )
            )
            withData(ios, android) {
                Warden(
                    AndroidAttestationConfiguration.Builder(
                        AndroidAttestationConfiguration.AppData(
                            "at.asitplus.cryptotest.androidApp",
                            androidSigDigests
                        )
                    ).build(),
                    IOSAttestationConfiguration(
                        IOSAttestationConfiguration.AppData(
                            "9CYHJNG644",
                            "at.asitplus.signumtest.iosApp",
                            sandbox = true
                        )
                    ),
                    FixedTimeClock(2024u, 10u, 1u),
                    verificationTimeOffset = 12.hours + 45.minutes

                ).apply {
                    withClue("should pass") {
                        verifyKeyAttestation(it.second, it.first.hexToByteArray(HexFormat.UpperCase)).apply {
                            isSuccess.shouldBeTrue()
                        }

                        val dbg = collectDebugInfo(
                            it.second,
                            it.first.hexToByteArray(HexFormat.UpperCase),
                        ).serializeCompact()
                        val replayKeyAttestation =
                            WardenDebugAttestationStatement.deserializeCompact(dbg)
                                .replayKeyAttestation(ignoreProxy = false)
                        replayKeyAttestation shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                            .replaySmart(ignoreProxy = false)
                        replayKeyAttestation.isSuccess.shouldBeTrue()

                    }

                    withClue("challenge fail pass") {
                        verifyKeyAttestation(it.second, it.first.reversed().hexToByteArray(HexFormat.UpperCase)).apply {
                            isSuccess.shouldBeFalse()
                        }
                        val dbg = collectDebugInfo(
                            it.second,
                            it.first.reversed().hexToByteArray(HexFormat.UpperCase)
                        ).serializeCompact()
                        val attestation = WardenDebugAttestationStatement.deserializeCompact(dbg)
                            .replayKeyAttestation(ignoreProxy = false)
                        attestation shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                            .replaySmart(ignoreProxy = false)
                        attestation.isSuccess.shouldBeFalse()
                    }
                }

                withClue("Invalid App ID") {
                    Warden(
                        AndroidAttestationConfiguration.Builder(
                            AndroidAttestationConfiguration.AppData(
                                "borked",
                                androidSigDigests
                            )
                        ).build(),
                        IOSAttestationConfiguration(
                            IOSAttestationConfiguration.AppData(
                                "9CYHJNG644",
                                "borked",
                                sandbox = true
                            )
                        ), FixedTimeClock(2024u, 10u, 1u)
                    ).apply {
                        verifyKeyAttestation(it.second, it.first.hexToByteArray(HexFormat.UpperCase)).apply {
                            isSuccess.shouldBeFalse()
                        }
                        val dbg = collectDebugInfo(
                            it.second,
                            it.first.hexToByteArray(HexFormat.UpperCase),
                        ).serializeCompact()
                        val replayKeyAttestation = WardenDebugAttestationStatement.deserializeCompact(dbg)
                            .replayKeyAttestation(ignoreProxy = false)
                        replayKeyAttestation shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                            .replaySmart(ignoreProxy = false)
                        replayKeyAttestation.isSuccess.shouldBeFalse()
                    }
                }

                withClue("Attestation created in the future") {
                    Warden(
                        AndroidAttestationConfiguration.Builder(
                            AndroidAttestationConfiguration.AppData(
                                "at.asitplus.cryptotest.androidApp",
                                androidSigDigests
                            )
                        ).build(),
                        IOSAttestationConfiguration(
                            IOSAttestationConfiguration.AppData(
                                "9CYHJNG644",
                                "at.asitplus.signumtest.iosApp",
                                sandbox = true
                            )
                        ),
                        FixedTimeClock(2024u, 10u, 1u),
                        verificationTimeOffset = 0.hours + 45.minutes

                    ).apply {
                        withClue("should pass") {
                            verifyKeyAttestation(it.second, it.first.hexToByteArray(HexFormat.UpperCase)).apply {
                                isSuccess.shouldBeFalse()
                            }
                            val dbg = collectDebugInfo(
                                it.second,
                                it.first.hexToByteArray(HexFormat.UpperCase),
                            ).serializeCompact()
                            val replayKeyAttestation = WardenDebugAttestationStatement.deserializeCompact(dbg)
                                .replayKeyAttestation(ignoreProxy = false)
                            replayKeyAttestation shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                .replaySmart(ignoreProxy = false)
                            replayKeyAttestation.isSuccess.shouldBeFalse()
                        }

                        withClue("challenge fail pass") {
                            verifyKeyAttestation(
                                it.second,
                                it.first.reversed().hexToByteArray(HexFormat.UpperCase)
                            ).apply {
                                isSuccess.shouldBeFalse()
                            }
                            val dbg = collectDebugInfo(
                                it.second,
                                it.first.hexToByteArray(HexFormat.UpperCase),
                            ).serializeCompact()
                            val replayKeyAttestation = WardenDebugAttestationStatement.deserializeCompact(dbg)
                                .replayKeyAttestation(ignoreProxy = false)
                            replayKeyAttestation shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                .replaySmart(ignoreProxy = false)
                            replayKeyAttestation.isSuccess.shouldBeFalse()
                        }
                    }
                }

                withClue("Verification Clock too far in the future (i.e. statement too old)") {
                    Warden(
                        AndroidAttestationConfiguration.Builder(
                            AndroidAttestationConfiguration.AppData(
                                "at.asitplus.cryptotest.androidApp",
                                androidSigDigests
                            )
                        ).build(),
                        IOSAttestationConfiguration(
                            IOSAttestationConfiguration.AppData(
                                "9CYHJNG644",
                                "at.asitplus.signumtest.iosApp",
                                sandbox = true
                            )
                        ),
                        FixedTimeClock(2024u, 10u, 1u),
                        verificationTimeOffset = 14.hours + 45.minutes

                    ).apply {
                        withClue("should pass") {
                            verifyKeyAttestation(it.second, it.first.hexToByteArray(HexFormat.UpperCase)).apply {
                                isSuccess.shouldBeFalse()
                            }
                            val dbg = collectDebugInfo(
                                it.second,
                                it.first.hexToByteArray(HexFormat.UpperCase),
                            ).serializeCompact()
                            val replayKeyAttestation = WardenDebugAttestationStatement.deserializeCompact(dbg)
                                .replayKeyAttestation(ignoreProxy = false)
                            replayKeyAttestation shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                .replaySmart(ignoreProxy = false)
                            replayKeyAttestation.isSuccess.shouldBeFalse()
                        }

                        withClue("challenge fail pass") {
                            verifyKeyAttestation(
                                it.second,
                                it.first.reversed().hexToByteArray(HexFormat.UpperCase)
                            ).apply {
                                isSuccess.shouldBeFalse()
                            }
                            val dbg = collectDebugInfo(
                                it.second,
                                it.first.hexToByteArray(HexFormat.UpperCase),
                            ).serializeCompact()
                            val replayKeyAttestation = WardenDebugAttestationStatement.deserializeCompact(dbg)
                                .replayKeyAttestation(ignoreProxy = false)
                            replayKeyAttestation shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                                .replaySmart(ignoreProxy = false)
                            replayKeyAttestation.isSuccess.shouldBeFalse()
                        }
                    }
                }

                withClue("Invalid Signature / Team ID") {
                    Warden(
                        AndroidAttestationConfiguration.Builder(
                            AndroidAttestationConfiguration.AppData(
                                "at.asitplus.cryptotest.androidApp",
                                listOf( //wrong digest
                                    "491A4513A3027563D3A6EA48EEE85BA45EB9F69CEEA19EF0EBB17F100BFC8878".hexToByteArray(
                                        HexFormat.UpperCase
                                    )
                                )
                            )
                        ).build(),
                        IOSAttestationConfiguration(
                            IOSAttestationConfiguration.AppData(
                                "borked1337",
                                "at.asitplus.signumtest.iosApp",
                                sandbox = true
                            )
                        ), FixedTimeClock(2024u, 10u, 1u)
                    ).apply {

                        verifyKeyAttestation(it.second, it.first.hexToByteArray(HexFormat.UpperCase)).apply {
                            isSuccess.shouldBeFalse()
                        }
                        val dbg = collectDebugInfo(
                            it.second,
                            it.first.hexToByteArray(HexFormat.UpperCase),
                        ).serializeCompact()
                        val replayKeyAttestation = WardenDebugAttestationStatement.deserializeCompact(dbg)
                            .replayKeyAttestation(ignoreProxy = false)
                        replayKeyAttestation shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                            .replaySmart(ignoreProxy = false)
                        replayKeyAttestation.isSuccess.shouldBeFalse()
                    }
                }

                withClue("Timewarp") {
                    Warden(
                        AndroidAttestationConfiguration.Builder(
                            AndroidAttestationConfiguration.AppData(
                                "at.asitplus.cryptotest.androidApp",
                                androidSigDigests
                            )
                        ).build(),
                        IOSAttestationConfiguration(
                            IOSAttestationConfiguration.AppData(
                                "9CYHJNG644",
                                "at.asitplus.signumtest.iosApp",
                                sandbox = true
                            )
                        ), FixedTimeClock(1954u, 10u, 1u)
                    ).apply {
                        verifyKeyAttestation(it.second, it.first.hexToByteArray(HexFormat.UpperCase)).apply {
                            isSuccess.shouldBeFalse()
                        }
                        val dbg = collectDebugInfo(
                            it.second,
                            it.first.hexToByteArray(HexFormat.UpperCase),
                        ).serializeCompact()
                        val replayKeyAttestation = WardenDebugAttestationStatement.deserializeCompact(dbg)
                            .replayKeyAttestation(ignoreProxy = false)
                        replayKeyAttestation shouldBe WardenDebugAttestationStatement.deserializeCompact(dbg)
                            .replaySmart(ignoreProxy = false)
                        replayKeyAttestation.isSuccess.shouldBeFalse()
                    }
                }
            }
        }
    }
}

