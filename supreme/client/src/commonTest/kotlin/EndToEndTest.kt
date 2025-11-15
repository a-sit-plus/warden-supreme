import at.asitplus.attestation.supreme.*
import at.asitplus.signum.supreme.os.PlatformSigningProvider
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.http.*

val ENDPOINT_CHALLENGE = "http://10.0.2.2:8080/api/v1/challenge"
val ENDPOINT_SHUTDOWN = "http://10.0.2.2:8080/shutdown"

val ALIAS = "ALIAS"

val EndToEndTest by testSuite {


    test("endToEnd") {
        PlatformSigningProvider.deleteSigningKey(ALIAS)
        val client = AttestationClient(HttpClient())
        val resp = client.getChallenge(Url(ENDPOINT_CHALLENGE))
        resp.isSuccess shouldBe true
        val attestationChallenge: AttestationChallenge = resp.getOrThrow()

        val csr = attestationChallenge.createAttestationProof(ALIAS).getOrThrow()
        val result = client.attest(csr, attestationChallenge.attestationEndpointUrl)
        val clue =
            if (result is AttestationResponse.Failure)
                result.kind.name + ": " + (result.explanation ?: "FAIL")
            else ""
        withClue(clue) { result.shouldBeInstanceOf<AttestationResponse.Success>() }

    }


    test("shutdown") {
        HttpClient().get(ENDPOINT_SHUTDOWN)
    }

}