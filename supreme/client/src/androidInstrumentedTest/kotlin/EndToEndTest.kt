package at.asitplus.attestation.test

import android.os.StrictMode
import androidx.test.filters.LargeTest
import androidx.test.filters.SmallTest
import at.asitplus.attestation.supreme.*
import at.asitplus.signum.supreme.os.PlatformSigningProvider
import io.kotest.assertions.withClue
import io.kotest.core.log
import io.kotest.engine.runBlocking
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.http.*
import org.junit.Before
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runners.MethodSorters


@LargeTest
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class EndToEndTest {


    val ENDPOINT_CHALLENGE = "http://10.0.2.2:8080/api/v1/challenge"
    val ENDPOINT_SHUTDOWN = "http://10.0.2.2:8080/shutdown"


    val alias = "ALIAS"
    lateinit var client: AttestationClient

    @Before
    fun setup() {
        StrictMode.setThreadPolicy(
            StrictMode.ThreadPolicy.Builder()
                .permitAll()
                .build()
        )
        StrictMode.setVmPolicy(
            StrictMode.VmPolicy.Builder()
                .build()
        )
        runBlocking {

            PlatformSigningProvider.deleteSigningKey(alias)
            client = AttestationClient(HttpClient())
        }
    }


    @Test
    fun EndToEndTest() {
        runBlocking {
            val resp = client.getChallenge(Url(ENDPOINT_CHALLENGE))
            log {resp.toString()}
            print(resp)
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
            log {clue}
            print(clue)
            System.err.println(clue)
            withClue(clue) { result.shouldBeInstanceOf<AttestationResponse.Success>() }
        }
    }

    @Test
    fun shutdown() {
        runBlocking {
            HttpClient().get(ENDPOINT_SHUTDOWN)
        }
    }

}