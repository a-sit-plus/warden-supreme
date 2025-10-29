package at.asitplus.attestation.test

import android.os.StrictMode
import at.asitplus.attestation.supreme.*
import at.asitplus.signum.supreme.os.PlatformSigningProvider
import de.infix.testBalloon.framework.testSuite
import io.kotest.assertions.withClue
import io.kotest.core.log
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.http.*

val EndToEndTest by testSuite {
    val ENDPOINT_CHALLENGE = "http://10.0.2.2:8080/api/v1/challenge"
    val ENDPOINT_SHUTDOWN = "http://10.0.2.2:8080/shutdown"

    val alias = "ALIAS"


    test("endToEnd") {
        StrictMode.setThreadPolicy(
            StrictMode.ThreadPolicy.Builder()
                .permitAll()
                .build()
        )
        StrictMode.setVmPolicy(
            StrictMode.VmPolicy.Builder()
                .build()
        )
        PlatformSigningProvider.deleteSigningKey(alias)
        val client: AttestationClient = AttestationClient(HttpClient())
        val resp = client.getChallenge(Url(ENDPOINT_CHALLENGE))
        System.err.println(resp)
        resp.isSuccess shouldBe true
        val attestationChallenge: AttestationChallenge = resp.getOrThrow()

        val signer = PlatformSigningProvider.createSigningKey(alias) {
            ec {}
            hardware {
                attestation {
                    this.challenge = attestationChallenge.nonce
                }
            }
        }.getOrThrow()

        val csr = signer.createCsr(attestationChallenge).getOrThrow()
        val result = client.attest(csr, attestationChallenge.attestationEndpointUrl)
        val clue =
            if (result is AttestationResponse.Failure)
                result.kind.name + ": " + (result.explanation ?: "FAIL")
            else ""
        System.err.println(clue)
        withClue(clue) { result.shouldBeInstanceOf<AttestationResponse.Success>() }
    }


    test("shutdown") {
        HttpClient().get(ENDPOINT_SHUTDOWN)
    }

}