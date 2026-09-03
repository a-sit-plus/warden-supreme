package at.asitplus.attestation.springtest

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * How emptiness is expressed in Spring Boot configuration.
 *
 * Spring Boot's `YamlProcessor` flattens `foo: []` and `foo: {}` into the *empty string* for the
 * property `foo` — the structure is gone before any binder sees it, and the result is
 * indistinguishable from an unresolved shell variable, a blank Helm value or an emptied CI secret.
 * A real application reported `revocation: []` failing with
 * `Expected JsonArray, but had JsonNull as the serialized body of kotlin.collections.ArrayList`.
 *
 * Silently reading that blank back as an empty list would mean an accidentally empty environment
 * variable switches revocation checking off, so `revocation` instead takes the explicit token
 * `DISABLED`, which survives every property source unchanged and round-trips through
 * `toYamlString()`. Blanks stay a hard error, and the error names the token.
 */
class EmptyCollectionBindingTest {

    @Test
    fun `the DISABLED token disables revocation checking`() {
        runApp(
            files = mapOf(
                "application.yaml" to """
                    attestation:
                      android:
                        applications:
                          - packageName: at.asitplus.disabled.revocation
                            signerFingerprints:
                              - ${Fixtures.SIGNER_FINGERPRINT}
                        revocation: DISABLED
                """.trimIndent()
            )
        ) { ctx ->
            val android = ctx.attestationProperties().androidConfig.orFail("android configuration")
            assertTrue(android.revocation.isEmpty(), "expected no revocation loaders, got ${android.revocation}")
            assertEquals(android, ctx.environmentLoader().android())
        }
    }

    @Test
    fun `the DISABLED token is matched case insensitively`() {
        listOf("DISABLED", "disabled", "Disabled").forEach { spelling ->
            runApp(
                files = mapOf(
                    "application.yaml" to """
                        attestation:
                          android:
                            applications:
                              - packageName: at.asitplus.disabled.case
                                signerFingerprints:
                                  - ${Fixtures.SIGNER_FINGERPRINT}
                            revocation: $spelling
                    """.trimIndent()
                )
            ) { ctx ->
                assertTrue(
                    ctx.attestationProperties().androidConfig.orFail("android configuration").revocation.isEmpty(),
                    "spelling '$spelling' did not disable revocation"
                )
            }
        }
    }

    @Test
    fun `the DISABLED token works from a flat properties file`() {
        runApp(
            files = mapOf(
                "application.properties" to """
                    attestation.android.applications[0].packageName=at.asitplus.disabled.props
                    attestation.android.applications[0].signerFingerprints[0]=${Fixtures.SIGNER_FINGERPRINT}
                    attestation.android.revocation=DISABLED
                """.trimIndent()
            )
        ) { ctx ->
            assertTrue(
                ctx.attestationProperties().androidConfig.orFail("android configuration").revocation.isEmpty()
            )
        }
    }

    @Test
    fun `the DISABLED token can override a populated list from the command line`() {
        runApp(
            files = mapOf(
                "application.yaml" to """
                    attestation:
                      android:
                        applications:
                          - packageName: at.asitplus.disabled.cli
                            signerFingerprints:
                              - ${Fixtures.SIGNER_FINGERPRINT}
                        revocation:
                          - type: google
                """.trimIndent()
            ),
            commandLineArgs = listOf("--attestation.android.revocation=DISABLED"),
        ) { ctx ->
            assertTrue(
                ctx.attestationProperties().androidConfig.orFail("android configuration").revocation.isEmpty()
            )
        }
    }

    @Test
    fun `the DISABLED token works from an environment variable`() {
        runApp(
            systemEnvironment = Fixtures.androidEnvironmentVariables("ATTESTATION_ANDROID", "at.asitplus.disabled.env") +
                mapOf("ATTESTATION_ANDROID_REVOCATION" to "DISABLED")
        ) { ctx ->
            assertTrue(
                ctx.attestationProperties().androidConfig.orFail("android configuration").revocation.isEmpty()
            )
        }
    }

    @Test
    fun `the DISABLED token works for a nested supreme config and both wiring styles agree`() {
        runApp(
            files = mapOf(
                "application.yaml" to """
                    attestation:
                      supreme:
                        clock: system
                        android:
                          applications:
                            - packageName: at.asitplus.disabled.supreme
                              signerFingerprints:
                                - ${Fixtures.SIGNER_FINGERPRINT}
                          revocation: DISABLED
                        ios:
                          applications:
                            - teamIdentifier: ${Fixtures.TEAM_IDENTIFIER}
                              bundleIdentifier: at.asitplus.disabled.supreme.ios
                """.trimIndent()
            )
        ) { ctx ->
            val supreme = ctx.attestationProperties().supremeConfig.orFail("supreme configuration")
            assertTrue(supreme.android.orFail("android configuration").revocation.isEmpty())
            assertEquals(supreme, ctx.environmentLoader().supreme())
        }
    }

    /**
     * The whole point of the token: a blank value must not disable a security control. `[]` and a
     * genuinely blank property are the same input by the time the loader sees them, so both fail, and
     * the message names `DISABLED` so the fix is obvious.
     */
    @Test
    fun `an empty or blank revocation value fails loudly and names the token`() {
        listOf("[]", "").forEach { spelling ->
            val diagnostics = startupFailureOf(
                files = mapOf(
                    "application.yaml" to """
                        attestation:
                          android:
                            applications:
                              - packageName: at.asitplus.blank.revocation
                                signerFingerprints:
                                  - ${Fixtures.SIGNER_FINGERPRINT}
                            revocation: $spelling
                    """.trimIndent()
                )
            )
            assertTrue(
                "DISABLED" in diagnostics && "an empty value" in diagnostics,
                "spelling '$spelling' produced unhelpful diagnostics: $diagnostics"
            )
        }
    }

    /**
     * `{}` behaves differently from `[]`, and safely so: an empty map contributes no properties at
     * all, so `revocation` is simply absent and keeps its default. Revocation checking stays *on*,
     * which is the right way for this to fail.
     */
    @Test
    fun `an empty map for revocation leaves the default in place rather than disabling anything`() {
        runApp(
            files = mapOf(
                "application.yaml" to """
                    attestation:
                      android:
                        applications:
                          - packageName: at.asitplus.emptymap.revocation
                            signerFingerprints:
                              - ${Fixtures.SIGNER_FINGERPRINT}
                        revocation: {}
                """.trimIndent()
            )
        ) { ctx ->
            val android = ctx.attestationProperties().androidConfig.orFail("android configuration")
            assertTrue(
                android.revocation.isNotEmpty(),
                "an empty map must not disable revocation, got ${android.revocation}"
            )
        }
    }

    @Test
    fun `a blank revocation environment variable fails instead of silently disabling revocation`() {
        val failure = runCatching {
            runApp(
                systemEnvironment = Fixtures.androidEnvironmentVariables("ATTESTATION_ANDROID", "at.asitplus.blank.env") +
                    mapOf("ATTESTATION_ANDROID_REVOCATION" to "")
            ) {}
        }.exceptionOrNull().orFail("failure for a blank revocation environment variable")
        assertTrue("DISABLED" in failure.messageChain(), "unexpected diagnostics: ${failure.messageChain()}")
    }

    @Test
    fun `an empty map still binds as empty where the option itself defaults to empty`() {
        runApp(
            files = mapOf(
                "application.yaml" to """
                    attestation:
                      android:
                        applications:
                          - packageName: at.asitplus.empty.custom.properties
                            signerFingerprints:
                              - ${Fixtures.SIGNER_FINGERPRINT}
                            customProperties: {}
                """.trimIndent()
            )
        ) { ctx ->
            val android = ctx.attestationProperties().androidConfig.orFail("android configuration")
            assertTrue(android.applications.single().customProperties.isEmpty())
            assertEquals(android, ctx.environmentLoader().android())
        }
    }

    @Test
    fun `an explicit null for a nullable option still binds to null`() {
        runApp(
            files = mapOf(
                "application.yaml" to """
                    attestation:
                      android:
                        applications:
                          - packageName: at.asitplus.explicit.null
                            signerFingerprints:
                              - ${Fixtures.SIGNER_FINGERPRINT}
                        androidVersion: null
                """.trimIndent()
            )
        ) { ctx ->
            assertNull(ctx.attestationProperties().androidConfig.orFail("android configuration").androidVersion)
        }
    }

    /**
     * `revocation` is the only collection where empty would be silently acceptable, which is why it
     * is the only one that needs a token. Every other collection is rejected when empty — though in
     * Spring the blank never reaches the configuration's own validation, so what surfaces is the raw
     * deserialization error rather than the domain message. Unpretty, but it does fail.
     */
    @Test
    fun `every other security relevant collection is rejected when empty`() {
        val emptyVerifiedBootKeys = startupFailureOf(
            files = mapOf(
                "application.yaml" to """
                    attestation:
                      android:
                        applications:
                          - packageName: at.asitplus.empty.guarded
                            signerFingerprints:
                              - ${Fixtures.SIGNER_FINGERPRINT}
                        verifiedBootKeys: []
                """.trimIndent()
            )
        )
        assertTrue("had JsonNull" in emptyVerifiedBootKeys, "verifiedBootKeys: $emptyVerifiedBootKeys")

        val emptyApplications = startupFailureOf(
            files = mapOf(
                "application.yaml" to """
                    attestation:
                      android:
                        applications: []
                """.trimIndent()
            )
        )
        assertTrue("had JsonNull" in emptyApplications, "applications: $emptyApplications")
    }

    /**
     * An in-memory revocation list with no entries stays unexpressible in Spring: an empty nested map
     * contributes no properties at all, so `list` disappears along with `entries`. This is a genuine
     * Spring Boot limitation rather than a loader defect — nothing survives for a loader to restore —
     * and `revocation: DISABLED` covers the case people actually want. Pinned so a future change in
     * Spring's flattening does not go unnoticed.
     */
    @Test
    fun `an empty in-memory revocation list is still not expressible in spring`() {
        val diagnostics = startupFailureOf(
            files = mapOf(
                "application.yaml" to """
                    attestation:
                      android:
                        applications:
                          - packageName: at.asitplus.empty.nested
                            signerFingerprints:
                              - ${Fixtures.SIGNER_FINGERPRINT}
                        revocation:
                          - type: mem
                            list:
                              entries: {}
                """.trimIndent()
            )
        )
        assertTrue("'list' is required" in diagnostics, "unexpected diagnostics: $diagnostics")
    }
}
