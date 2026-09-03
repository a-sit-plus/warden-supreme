package at.asitplus.attestation.springtest

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Spring Boot binding semantics that the loader has to survive: relaxed property spellings,
 * placeholder resolution and the documented property-source precedence.
 */
class BindingSemanticsTest {

    @Test
    fun `relaxed property spellings all reach the same configuration`() {
        listOf("packageName", "package-name", "package_name").forEach { spelling ->
            runApp(
                files = mapOf(
                    "application.yaml" to """
                        attestation:
                          android:
                            applications:
                              - $spelling: at.asitplus.relaxed
                                signerFingerprints:
                                  - ${Fixtures.SIGNER_FINGERPRINT}
                    """.trimIndent()
                )
            ) { ctx ->
                runCatching { ctx.assertAndroidPackage("at.asitplus.relaxed") }
                    .onFailure { error("spelling '$spelling' did not bind: ${it.message}") }
            }
        }
    }

    @Test
    fun `relaxed spellings also apply to nested and kebab cased option names`() {
        runApp(
            files = mapOf(
                "application.yaml" to """
                    attestation:
                      android:
                        applications:
                          - packageName: at.asitplus.kebab
                            signerFingerprints:
                              - ${Fixtures.SIGNER_FINGERPRINT}
                        verification-seconds-offset: 33
                        require-strong-box: true
                        revocation:
                          - type: google
                            fallback-revocation-list-validity-seconds: 90
                """.trimIndent()
            )
        ) { ctx ->
            val android = ctx.attestationProperties().androidConfig.orFail("android configuration")
            assertEquals(33, android.verificationSecondsOffset)
            assertTrue(android.requireStrongBox)
            assertEquals(1, android.revocation.size)
            assertEquals(android, ctx.environmentLoader().android())
        }
    }

    @Test
    fun `placeholders are resolved before the loader sees the value`() {
        runApp(
            files = mapOf(
                "application.yaml" to """
                    app:
                      package: at.asitplus.placeholder
                    attestation:
                      android:
                        applications:
                          - packageName: ${'$'}{app.package}
                            signerFingerprints:
                              - ${'$'}{app.fingerprint:${Fixtures.SIGNER_FINGERPRINT}}
                """.trimIndent()
            )
        ) { ctx ->
            ctx.assertAndroidPackage("at.asitplus.placeholder")
        }
    }

    @Test
    fun `higher precedence property sources win without breaking the structure`() {
        runApp(
            files = mapOf(
                "application.yaml" to """
                    attestation:
                      android:
                        applications:
                          - packageName: at.asitplus.from.file
                            signerFingerprints:
                              - ${Fixtures.SIGNER_FINGERPRINT}
                        verificationSecondsOffset: 1
                        requireRemoteKeyProvisioning: false
                """.trimIndent()
            ),
            highestPrecedenceProperties = mapOf(
                "attestation.android.verificationSecondsOffset" to 123,
                "attestation.android.requireRemoteKeyProvisioning" to true,
            ),
        ) { ctx ->
            val android = ctx.attestationProperties().androidConfig.orFail("android configuration")
            assertEquals("at.asitplus.from.file", android.applications.single().packageName)
            assertEquals(123, android.verificationSecondsOffset)
            assertEquals(android, ctx.environmentLoader().android())
        }
    }

    @Test
    fun `command line arguments outrank configuration files`() {
        runApp(
            files = mapOf(
                "application.yaml" to """
                    attestation:
                      android:
                        applications:
                          - packageName: at.asitplus.from.file
                            signerFingerprints:
                              - ${Fixtures.SIGNER_FINGERPRINT}
                        verificationSecondsOffset: 1
                """.trimIndent()
            ),
            commandLineArgs = listOf("--attestation.android.verificationSecondsOffset=55"),
        ) { ctx ->
            assertEquals(
                55,
                ctx.attestationProperties().androidConfig.orFail("android configuration").verificationSecondsOffset
            )
        }
    }

    @Test
    fun `a list element can be replaced through a higher precedence source`() {
        runApp(
            files = mapOf(
                "application.yaml" to """
                    attestation:
                      android:
                        applications:
                          - packageName: at.asitplus.from.file
                            signerFingerprints:
                              - ${Fixtures.SIGNER_FINGERPRINT}
                """.trimIndent()
            ),
            highestPrecedenceProperties = mapOf(
                "attestation.android.applications[0].packageName" to "at.asitplus.overridden",
            ),
        ) { ctx ->
            ctx.assertAndroidPackage("at.asitplus.overridden")
        }
    }

    @Test
    fun `an absent prefix is reported instead of silently yielding a default configuration`() {
        runApp(files = mapOf("application.yaml" to "unrelated: true")) { ctx ->
            val failure = runCatching { ctx.environmentLoader().android() }.exceptionOrNull()
                .orFail("failure for an absent prefix")
            assertTrue(
                "attestation.android" in failure.messageChain(),
                "unexpected diagnostics: ${failure.messageChain()}"
            )
        }
    }
}
