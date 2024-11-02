import at.asitplus.signum.supreme.os.PlatformSigningProvider
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.attestation.supreme.AttestationChallenge
import at.asitplus.attestation.supreme.AttestationClient
import at.asitplus.attestation.supreme.AttestationResponse
import at.asitplus.attestation.supreme.attestationEndpointUrl
import at.asitplus.attestation.supreme.createCsr
import br.com.colman.kotest.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.http.*
import org.junit.runner.RunWith


@RunWith(br.com.colman.kotest.KotestRunnerAndroid::class)
class EndToEndTest : FreeSpec({


    val ENDPOINT_CHALLENGE = "http://10.0.2.2:8080/api/v1/challenge"
    val ENDPOINT_SHUTDOWN = "http://10.0.2.2:8080/shutdown"

    "OK" - {
        val alias = "ALIAS"
        PlatformSigningProvider.deleteSigningKey(alias)
        val client = AttestationClient(HttpClient())
        lateinit var challenge: AttestationChallenge
        "GET challenge" {
            val resp = client.getChallenge(Url(ENDPOINT_CHALLENGE))
            resp.isSuccess shouldBe true
            challenge = resp.getOrThrow()
        }

        lateinit var signer: Signer.Attestable<*>

        "Create Signer" {
            signer = PlatformSigningProvider.createSigningKey(alias) {
                ec {}
                hardware {
                    attestation {
                        this.challenge = challenge.nonce
                    }
                }
            }.getOrThrow()
        }

        "POST attestation" {
            val csr = signer.createCsr(challenge).getOrThrow()
            val result = client.attest(csr, challenge.attestationEndpointUrl)
            result.shouldBeInstanceOf<AttestationResponse.Success>()
        }
    }

    "Shutdown" {
        HttpClient().get(ENDPOINT_SHUTDOWN)
    }
})