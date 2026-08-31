package at.asitplus.attestation.android

import at.asitplus.attestation.wardenVersion
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.toJcaCertificateBlocking
import at.asitplus.signum.indispensable.toJcaPublicKey
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import net.mamoe.yamlkt.Yaml
import java.security.KeyPairGenerator
import kotlin.reflect.KClass
import kotlin.time.Clock

private data class TrustedRootFixture(
    val name: String,
    val yaml: String,
    val json: String,
    val expectedClass: KClass<out TrustedRoot>,
    val expectedPem: String,
    val caName: String? = null,
    val enforceFactoryProvisionedChainValidity: Boolean? = null,
)

private val CERTIFICATE_PEM = """
    -----BEGIN CERTIFICATE-----
    MIIB8zCCAXqgAwIBAgIRAMxm6ak3E7bmQ7JsFYeXhvcwCgYIKoZIzj0EAwIwOTEMMAoGA1UEDAwDVEVFMSkwJwYDVQQFEyA0ZjdlYzg1N2U4MDU3
    NDdjMWIxZWRhYWVmODk1NDk2ZDAeFw0xOTA4MTQxOTU0MTBaFw0yOTA4MTExOTU0MTBaMDkxDDAKBgNVBAwMA1RFRTEpMCcGA1UEBRMgMzJmYmJi
    NmRiOGM5MTdmMDdhYzlhYjZhZTQ4MTAzYWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQzg+sx9lLrkNIZwLYZerzL1bPK2zi75zFEuuI0fIr3
    5DJND1B4Z8RPZ3djzo3FOdAObqvoZ4CZVxcY3iQ1ffMMo2MwYTAdBgNVHQ4EFgQUzZOUqhJOO7wttSe9hYemjceVsgIwHwYDVR0jBBgwFoAUWlnI
    9iPzasns60heYXIP+h+Hz8owDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwCgYIKoZIzj0EAwIDZwAwZAIwUFz/AKheCOPaBiRGDk7L
    aSEDXVYmTr0VoU8TbIqrKGWiiMwsGEmW+Jdo8EcKVPIwAjAoO7n1ruFh+6mEaTAukc6T5BW4MnmYadkkFSIjzDAaJ6lAq+nmmGQ1KlZpqi4Z/VI=
    -----END CERTIFICATE-----
""".trimIndent()

private val PUBLIC_KEY_PEM = """
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqs5NcBOKN40tu/5+NLFvGRMRcYF6KRksYoUmiwlKhhzbGaALzE2PerEM5wzNKeC6ESruZJRoBPuHn5D+HfoMkA==
    -----END PUBLIC KEY-----
""".trimIndent()

private fun yamlScalar(pem: String) = "|\n${pem.prependIndent("  ")}"
private fun yamlList(pem: String, vararg values: String) =
    values.joinToString("\n") { "- $it" } + "\n- |\n${pem.prependIndent("    ")}"

private fun String.asJsonLiteral(): String = "\"${replace("\\", "\\\\").replace("\n", "\\n").replace("\"", "\\\"")}\""

private val CERTIFICATE_JSON = CERTIFICATE_PEM.asJsonLiteral()
private val PUBLIC_KEY_JSON = PUBLIC_KEY_PEM.asJsonLiteral()

val SerializationRegressionTests by matrixSuite {

    data(
        "trusted root string representations",
        listOf(
            TrustedRootFixture(
                "certificate",
                yamlScalar(CERTIFICATE_PEM),
                CERTIFICATE_JSON,
                TrustedRoot.Certificate::class,
                CERTIFICATE_PEM,
            ),
            TrustedRootFixture(
                "Android-specific certificate",
                yamlList(CERTIFICATE_PEM, "false"),
                "[false, $CERTIFICATE_JSON]",
                TrustedRoot.Certificate.AndroidSpecific::class,
                CERTIFICATE_PEM,
                enforceFactoryProvisionedChainValidity = false,
            ),
            TrustedRootFixture(
                "public key",
                yamlScalar(PUBLIC_KEY_PEM),
                PUBLIC_KEY_JSON,
                TrustedRoot.PublicKey::class,
                PUBLIC_KEY_PEM,
            ),
            TrustedRootFixture(
                "public key with CA name",
                yamlList(PUBLIC_KEY_PEM, "CN=Test Root"),
                "[\"CN=Test Root\", $PUBLIC_KEY_JSON]",
                TrustedRoot.PublicKey::class,
                PUBLIC_KEY_PEM,
                caName = "CN=Test Root",
            ),
            TrustedRootFixture(
                "Android-specific public key",
                yamlList(PUBLIC_KEY_PEM, "true"),
                "[true, $PUBLIC_KEY_JSON]",
                TrustedRoot.PublicKey.AndroidSpecific::class,
                PUBLIC_KEY_PEM,
                enforceFactoryProvisionedChainValidity = true,
            ),
            TrustedRootFixture(
                "Android-specific public key with CA name",
                yamlList(PUBLIC_KEY_PEM, "false", "CN=Test Root"),
                "[false, \"CN=Test Root\", $PUBLIC_KEY_JSON]",
                TrustedRoot.PublicKey.AndroidSpecific::class,
                PUBLIC_KEY_PEM,
                caName = "CN=Test Root",
                enforceFactoryProvisionedChainValidity = false,
            ),
        ),
        nameFn = { _, fixture -> fixture.name },
    ) - { fixture ->
        data(
            "format",
            listOf("YAML" to fixture.yaml, "JSON" to fixture.json),
            nameFn = { _, (format, _) -> format },
        ) test { (format, serialized) ->
            val root = if (format == "YAML") {
                Yaml.decodeFromString<TrustedRoot>(serialized)
            } else {
                Json.decodeFromString<TrustedRoot>(serialized)
            }

            root::class shouldBe fixture.expectedClass
            (root as? TrustedRoot.PublicKey)?.caName?.name shouldBe fixture.caName
            (root as? TrustedRoot.AndroidSpecific)?.enforceFactoryProvisionedChainValidity shouldBe
                    fixture.enforceFactoryProvisionedChainValidity
            when (root) {
                is TrustedRoot.PublicKey -> root.publicKey.encoded.contentEquals(
                    CryptoPublicKey.decodeFromPem(fixture.expectedPem).getOrThrow().toJcaPublicKey()
                        .getOrThrow().encoded
                ) shouldBe true

                is TrustedRoot.Certificate -> root.certificate.encoded.contentEquals(
                    X509Certificate.decodeFromPem(fixture.expectedPem).getOrThrow().toJcaCertificateBlocking()
                        .getOrThrow().encoded
                ) shouldBe true
            }
        }
    }

    "AndroidDebugAttestationStatement can be serialized (TrustedRootSerializer init)" {
        val keyPair = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
        val trustedRoot = TrustedRoot.PublicKey(keyPair.public)

        val configuration = AndroidAttestationConfiguration(
            applications = listOf(
                AndroidAttestationConfiguration.AppData(
                    packageName = "at.asitplus.test",
                    signerFingerprints = setOf(ByteArray(32))
                )
            ),
            hardwareTrustedRoots = setOf(trustedRoot),
            softwareTrustedRoots = setOf(trustedRoot),
            revocation = emptyList(),
        )

        val statement = AndroidDebugAttestationStatement(
            version = wardenVersion,
            configuration = configuration,
            verificationTime = Clock.System.now(),
            challenge = ByteArray(16),
            attestationStatement = emptyList(),
            revocationLists = emptyList(),
        )

        val compact = statement.serializeCompact()
        val decoded = AndroidDebugAttestationStatement.deserializeCompact(compact)
        decoded.version shouldBe wardenVersion
    }

    "Roboto retains at most 100 revocation snapshots and consumes matches" {
        val keyPair = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
        val trustedRoot = TrustedRoot.PublicKey(keyPair.public)
        val roboto = Roboto(
            AndroidAttestationConfiguration(
                applications = listOf(
                    AndroidAttestationConfiguration.AppData(
                        packageName = "at.asitplus.test",
                        signerFingerprints = setOf(ByteArray(32)),
                    )
                ),
                hardwareTrustedRoots = setOf(trustedRoot),
                softwareTrustedRoots = setOf(trustedRoot),
                revocation = emptyList(),
            )
        )
        val revocationList = AndroidRevocationList(emptyMap())
        val snapshot = listOf(
            ConfigWithList(AndroidRevocationList.InMemoryLoader.Configuration(revocationList), revocationList)
        )

        repeat(101) { roboto.rememberRevocationLists(byteArrayOf(it.toByte()), snapshot) }

        roboto.revocationListsForChallenge(byteArrayOf(0)) shouldBe emptyList()
        roboto.revocationListsForChallenge(byteArrayOf(1)) shouldBe snapshot
        roboto.revocationListsForChallenge(byteArrayOf(1)) shouldBe emptyList()
        roboto.revocationListsForChallenge(byteArrayOf(127)) shouldBe emptyList()
    }
}
