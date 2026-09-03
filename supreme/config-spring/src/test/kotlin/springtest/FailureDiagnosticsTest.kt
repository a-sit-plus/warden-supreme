package at.asitplus.attestation.springtest

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * A misconfigured application must fail to start, with diagnostics that name the offending option.
 * These run the real application, so the assertions cover what an operator actually sees.
 */
class FailureDiagnosticsTest {

    @Test
    fun `an incomplete application entry fails start-up naming the missing option`() {
        val diagnostics = startupFailureOf(
            files = mapOf(
                "application.yaml" to """
                    attestation:
                      android:
                        applications:
                          - packageName: at.asitplus.incomplete
                """.trimIndent()
            )
        )
        assertTrue("signerFingerprints" in diagnostics, "unexpected diagnostics: $diagnostics")
    }

    @Test
    fun `an unknown revocation loader type fails start-up naming the type`() {
        val diagnostics = startupFailureOf(
            files = mapOf(
                "application.yaml" to """
                    attestation:
                      android:
                        applications:
                          - packageName: at.asitplus.unknown.loader
                            signerFingerprints:
                              - ${Fixtures.SIGNER_FINGERPRINT}
                        revocation:
                          - type: definitely-not-a-loader
                """.trimIndent()
            )
        )
        assertTrue("definitely-not-a-loader" in diagnostics, "unexpected diagnostics: $diagnostics")
    }

    /**
     * `21E236` is valid YAML for a float in scientific notation, so it has to be quoted. Spring Boot
     * hands the loader a number, and the resulting failure has to point at `buildNumber`.
     */
    @Test
    fun `an unquoted iOS build number fails start-up naming buildNumber`() {
        val diagnostics = startupFailureOf(
            files = mapOf(
                "application.yaml" to """
                    attestation:
                      ios:
                        applications:
                          - teamIdentifier: ${Fixtures.TEAM_IDENTIFIER}
                            bundleIdentifier: at.asitplus.unquoted
                        iosVersion:
                          semVer: 17.4.1
                          buildNumber: 21E236
                """.trimIndent()
            )
        )
        assertTrue("buildNumber" in diagnostics, "unexpected diagnostics: $diagnostics")
    }

    @Test
    fun `a quoted iOS build number loads`() {
        runApp(
            files = mapOf(
                "application.yaml" to """
                    attestation:
                      ios:
                        applications:
                          - teamIdentifier: ${Fixtures.TEAM_IDENTIFIER}
                            bundleIdentifier: at.asitplus.quoted
                        iosVersion:
                          semVer: 17.4.1
                          buildNumber: "21E236"
                """.trimIndent()
            )
        ) { ctx ->
            val ios = ctx.attestationProperties().iosConfig.orFail("iOS configuration")
            assertEquals("at.asitplus.quoted", ios.applications.single().bundleIdentifier)
            assertEquals(ios, ctx.environmentLoader().ios())
        }
    }
}
