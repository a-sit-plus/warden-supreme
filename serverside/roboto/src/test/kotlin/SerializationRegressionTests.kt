package at.asitplus.attestation.android

import at.asitplus.attestation.wardenVersion
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import java.security.KeyPairGenerator
import java.util.Date
import kotlin.time.Clock

val SerializationRegressionTests by testSuite {

    "AndroidDebugAttestationStatement can be serialized (TrustedRootSerializer init)" {
        val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val trustedRoot = TrustedRoot.PublicKey(keyPair.public)

        val configuration = AndroidAttestationConfiguration(
            applications = listOf(
                AndroidAttestationConfiguration.AppData(
                    packageName = "at.asitplus.test",
                    signerFingerprints = listOf(ByteArray(32))
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
}
