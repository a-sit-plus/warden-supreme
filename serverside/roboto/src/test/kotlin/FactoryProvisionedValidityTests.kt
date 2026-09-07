package at.asitplus.attestation.android

import at.asitplus.attestation.android.engine.JvmCertChainValidator
import at.asitplus.attestation.android.exceptions.CertificateInvalidException
import at.asitplus.testballoon.matrix.*
import com.android.keyattestation.verifier.provider.KeyAttestationCertPath
import com.android.keyattestation.verifier.provider.ProvisioningMethod
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Date

private val expiredFactoryProvisionedChain: List<X509Certificate> = listOf(
        "MIIChTCCAiqgAwIBAgIBATAKBggqhkjOPQQDAjApMRkwFwYDVQQFExBmN2NmZWQ2ZGFlNDg2ZjY3MQwwCgYDVQQMDANURUUwHhcNNzAwMTAxMDAwMDAwWhcNMzcxMjE1MDAwMDAwWjAfMR0wGwYDVQQDDBRBbmRyb2lkIEtleXN0b3JlIEtleTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMSuy-5NnU4G0SdpOTjz8DIPJBVNHIULR4WcbIo1C7ck_gAlf9H6hBTYQnvTXxqNevamDGlGGZp9wLkCbo0QdYWjggFLMIIBRzAOBgNVHQ8BAf8EBAMCB4AwggEzBgorBgEEAdZ5AgERBIIBIzCCAR8CAQMKAQECAQQKAQEEIKNqlBMmRxhd1jlrWDkGqjGm6SopXCPpO8V8XYB6wseOBAAwXb-FPQgCBgGgGyWNaL-FRU0ESzBJMSMwIQQcYXQuYXNpdHBsdXMud2FyZGVuLmNvbGxlY3RvcgIBAzEiBCAbpk5FdABLn6srBz8W-zsNNrscL0V8ovA_WigAk3wd2jCBjaEFMQMCAQKiAwIBA6MEAgIBAKUFMQMCAQSqAwIBAb-DdwIFAL-FPgMCAQC_hUBMMEoEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQEACgECBCDBKI4e7CdlSEqituEkojS9iZN9oSkjzln4Yovwh2zIeL-FQQUCAwHUwL-FQgUCAwMV2jAKBggqhkjOPQQDAgNJADBGAiEA-qJyTOvmAfTqtT7e0dP0Kd4dkDVBwLPXgkQ3nzRVZNICIQD0qBGWkovZjcySKwIgQa8Zg7qA9dWW7zKGdAmQU0jfVg",
        "MIICJDCCAaugAwIBAgIKFneJCSWHEnGWgDAKBggqhkjOPQQDAjApMRkwFwYDVQQFExBhODRkNDhiOWNmNzJiYjc3MQwwCgYDVQQMDANURUUwHhcNMTkwNjI2MjEyNjQ5WhcNMjkwNjIzMjEyNjQ5WjApMRkwFwYDVQQFExBmN2NmZWQ2ZGFlNDg2ZjY3MQwwCgYDVQQMDANURUUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQfEtIyAJ4x-XYyKfBkuFjdFZkISbK3nxfZ8l_T_NqJVcJDiD4R1d73Z82Ul5WEKvHUfCdXMDyPXISCkbvdVfF1o4G6MIG3MB0GA1UdDgQWBBR8NM4ckbAYo3HzFSVxjgz9ZVIkKzAfBgNVHSMEGDAWgBRLlpGPfwsbbhGYlwf6HF6NiRX0TTAPBgNVHRMBAf8EBTADAQH_MA4GA1UdDwEB_wQEAwICBDBUBgNVHR8ETTBLMEmgR6BFhkNodHRwczovL2FuZHJvaWQuZ29vZ2xlYXBpcy5jb20vYXR0ZXN0YXRpb24vY3JsLzE2Nzc4OTA5MjU4NzEyNzE5NjgwMAoGCCqGSM49BAMCA2cAMGQCMH9Qg82wUnRNprSw5gSWfUc_XTE_yxIKMW3M3Q7nKMpG4qqvSePKzeLfU80f87SBSgIwMXD3ojsJVfeXwPwv131uHG5AWDUNAFTUmaEI8l_mGEzrXXcj5yJW5QskD5vY57tt",
        "MIID0TCCAbmgAwIBAgIKA4gmZ2BliZaF5DANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MB4XDTE5MDYyNjIxMjYwOFoXDTI5MDYyMzIxMjYwOFowKTEZMBcGA1UEBRMQYTg0ZDQ4YjljZjcyYmI3NzEMMAoGA1UEDAwDVEVFMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEuAoOW7eZeb3mE9gsjxrWKyDeKJ93vRjX8ygYY6q7sZ8wvHoOMi-CmP2rYJyRQ5dNOwuEUM5SV4QHktjOXbPXqHC5Hu-3Slnb-s6eBwgydM6WOW2GpkOudmqctNannmuIo4G2MIGzMB0GA1UdDgQWBBRLlpGPfwsbbhGYlwf6HF6NiRX0TTAfBgNVHSMEGDAWgBQ2YeEAfIgFCVGLRGxH_xpMyepPEjAPBgNVHRMBAf8EBTADAQH_MA4GA1UdDwEB_wQEAwICBDBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwczovL2FuZHJvaWQuZ29vZ2xlYXBpcy5jb20vYXR0ZXN0YXRpb24vY3JsL0U4RkExOTYzMTREMkZBMTgwDQYJKoZIhvcNAQELBQADggIBAJmoTeXPpdYa2yv7r9305fv6zdZf7fFv5ip8cyXnsNw9CD6v6f03Hvb92f-aWfLIFdI0rQuZ_-WKrOcFSP2KDsYR7FOmX7Kds3nmeQyrT_u_p5dKEKcmwAtZufEgYSo5sMQdv2wiysXEa523nYR1pf1wwcEcMbyPYmHYqRWURVysvq0H2TshFZqo1Ztn1n7a3li84brfBBWh0NBc4CnpX9eQpZbISO8C8Vv0VJNCb2u9Vu6TLyeUvM6C4Om8rfKOgFk8VAXMvCKMunGrURua2uaX0W29raXoCDW8Z-O_IYcWUn1FLMEGVX2QeW2IWurqlbCb37XQ3ju4sKDV6FO2vUS9zc2DOU279q8d9aGAjfJluScJYFHDOVrxg8rtr0uFecVYeFcq6azReoS6MUMAf_WWavMuHf-s0S3LiqJpn_pDFoqAdvm-UdcORYY7iGRlp6vhidogqkRLT2py38SL-zMP5CLnbZeMAfk5gutBNWSse13jrSEHav7Z2oTUDgJtml41voX4nwOWGDFykWlhz-S6MrQjkw2gSzWHVEs8ZSdD15pK7hUWo8-zfbpDMe4c2Iij1ssIBkcOw-L6BYLBql5f5E2HOKC8o-qKFJilohdKPrx9XyJ7Th3V4UiFsYSGY-tz4WJlabLGZnt5nJsVwXHRr8WpIRBUP5n9ucHMoWa1",
        "MIIFYDCCA0igAwIBAgIJAOj6GWMU0voYMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTYwNTI2MTYyODUyWhcNMjYwNTI0MTYyODUyWjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd_dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy_4lj4_7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1-di-y9TFRtv6y__0rb-T-W8a9nsNL_ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB_M0n1n_W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl_m00QLVWutHQoVJYnFPlXTcHYvASLu-RhhsbDmxMgJJ0mcDpvsC4PjvB-TxywElgS70vE0XmLD-OJtvsBslHZvPBKCOdT0MS-tgSOIfga-z1Z1g7-DVagf7quvmag8jfPioyKvxnK_EgsTUVi2ghzq8wm27ud_mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws-W0rB5N-er5_2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI_-MRPjy02i59lINMRRev56GKtcd9qO_0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab-9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ-8PTWm2QgBR_bkwSWc-NpUFgNPN9PvQi8WEg5UmAGMCAwEAAaOBpjCBozAdBgNVHQ4EFgQUNmHhAHyIBQlRi0RsR_8aTMnqTxIwHwYDVR0jBBgwFoAUNmHhAHyIBQlRi0RsR_8aTMnqTxIwDwYDVR0TAQH_BAUwAwEB_zAOBgNVHQ8BAf8EBAMCAYYwQAYDVR0fBDkwNzA1oDOgMYYvaHR0cHM6Ly9hbmRyb2lkLmdvb2dsZWFwaXMuY29tL2F0dGVzdGF0aW9uL2NybC8wDQYJKoZIhvcNAQELBQADggIBACDIw41L3KlXG0aMiS__cqrG-EShHUGo8HNsw30W1kJtjn6UBwRM6jnmiwfBPb8VA91chb2vssAtX2zbTvqBJ9-LBPGCdw_E53Rbf86qhxKaiAHOjpvAy5Y3m00mqC0w_Zwvju1twb4vhLaJ5NkUJYsUS7rmJKHHBnETLi8GFqiEsqTWpG_6ibYCv7rYDBJDcR9W62BW9jfIoBQcxUCUJouMPH25lLNcDc1ssqvC2v7iUgI9LeoM1sNovqPmQUiG9rHli1vXxzCyaMTjwftkJLkf6724DFhuKug2jITV0QkXvaJWF4nUaHOTNA4uJU9WDvZLI1j83A-_xnAJUucIv_zGJ1AMH2boHqF8CY16LpsYgBt6tKxxWH00XcyDCdW2KlBCeqbQPcsFmWyWugxdcekhYsAWyoSf818NUsZdBWBaR_OukXrNLfkQ79IyZohZbvabO_X-MVT3rriAoKc8oE2Uws6DF-60PV7_WIPjNvXySdqspImSN78mflxDqwLqRBYkA3I75qppLGG9rp7UCdRjxMl8ZDBld-7yvHVgt1cVzJx9xnyGCC23UaicMDSXYrB4I4WHXPGjxhZuCuPBLTdOLU8YRvMYdEvYebWHMpvwGCF6bAx3JBpIeOQ1wDB5y0USicV3YgYGmi-NZfhA4URSh77Yd6uuJOJENRaNVTzk"
).map {
    CertificateFactory.getInstance("X.509")
        .generateCertificate(Base64.getUrlDecoder().decode(it).inputStream()) as X509Certificate
}

private data class FactoryValidityPolicyCase(
    val name: String,
    val roots: (X509Certificate) -> Set<TrustedRoot>,
    val globalPolicy: Boolean,
    val validityEnforced: Boolean,
)

private val factoryValidityPolicyCases = listOf(
    FactoryValidityPolicyCase(
        name = "default root policy false overrides global true",
        roots = { GOOGLE_DEFAULT_HARDWARE_TRUST_ANCHORS },
        globalPolicy = true,
        validityEnforced = false,
    ),
    FactoryValidityPolicyCase(
        name = "generic root inherits global false",
        roots = { setOf(TrustedRoot.Certificate(it)) },
        globalPolicy = false,
        validityEnforced = false,
    ),
    FactoryValidityPolicyCase(
        name = "generic root inherits global true",
        roots = { setOf(TrustedRoot.Certificate(it)) },
        globalPolicy = true,
        validityEnforced = true,
    ),
    FactoryValidityPolicyCase(
        name = "root policy false overrides global true",
        roots = { setOf(TrustedRoot.Certificate(it, false)) },
        globalPolicy = true,
        validityEnforced = false,
    ),
    FactoryValidityPolicyCase(
        name = "root policy true overrides global false",
        roots = { setOf(TrustedRoot.Certificate(it, true)) },
        globalPolicy = false,
        validityEnforced = true,
    ),
)

private data class InvalidVerificationTime(val name: String, val value: Date)

private val invalidVerificationTimes = listOf(
    InvalidVerificationTime("before factory chain validity", Date(0)),
    InvalidVerificationTime("after expired factory root validity", Date(1_787_161_841_378)),
)

val FactoryProvisionedValidityTests by matrixSuite {
    "factory-provisioned validity policy precedence" - {
        KeyAttestationCertPath(expiredFactoryProvisionedChain).provisioningMethod() shouldBe
                ProvisioningMethod.FACTORY_PROVISIONED

        data(
            "policy",
            factoryValidityPolicyCases,
            nameFn = { _, value -> value.name },
        ) - { policy ->
            data(
                "verification time",
                invalidVerificationTimes,
                nameFn = { _, value -> value.name },
            ) - { verificationTime ->
                "resolves root policy before the global policy" {
                    val roots = policy.roots(expiredFactoryProvisionedChain.last())
                    val validator = JvmCertChainValidator(
                        AndroidAttestationConfiguration(
                            applications = listOf(
                                AndroidAttestationConfiguration.AppData(
                                    packageName = "unused",
                                    signerFingerprints = setOf(byteArrayOf(1)),
                                )
                            ),
                            hardwareTrustedRoots = roots,
                            revocation = emptyList(),
                            enforceFactoryProvisionedChainValidity = policy.globalPolicy,
                        )
                    )

                    if (policy.validityEnforced) {
                        shouldThrow<CertificateInvalidException> {
                            validator.run {
                                expiredFactoryProvisionedChain.verifyCertificateChain(
                                    verificationTime.value,
                                    roots,
                                    requireRKP = false,
                                ).verdict.getOrThrow()
                            }
                        }.reason shouldBe CertificateInvalidException.Reason.TIME
                    } else {
                        validator.run {
                            expiredFactoryProvisionedChain.verifyCertificateChain(
                                verificationTime.value,
                                roots,
                                requireRKP = false,
                            ).verdict.getOrThrow()
                        }
                    }
                }
            }
        }
    }
}
