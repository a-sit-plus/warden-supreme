import android.Manifest
import android.Manifest.permission.ACCESS_NETWORK_STATE
import androidx.test.rule.GrantPermissionRule
import at.asitplus.signum.indispensable.AndroidKeystoreAttestation
import at.asitplus.signum.supreme.os.PlatformSigningProvider
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.veritatis.*
import br.com.colman.kotest.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.client.*
import io.ktor.http.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Rule
import org.junit.runner.RunWith


@OptIn(ExperimentalStdlibApi::class)
@RunWith(br.com.colman.kotest.KotestRunnerAndroid::class)
class EndToEndTest : FreeSpec({


    val ENDPOINT_CHALLENGE = "http://10.0.2.2:8080/api/v1/challenge"



    "OK" - {
        val alias = "ALIAS"
        PlatformSigningProvider.deleteSigningKey(alias)
        val servus = Servus(HttpClient())
        lateinit var challenge: AttestationChallenge
        "GET challange" {
            val resp = servus.getChallenge(Url(ENDPOINT_CHALLENGE))
            resp.isSuccess shouldBe true
            challenge = resp.getOrThrow()
        }

        lateinit var signer: Signer.Attestable<AndroidKeystoreAttestation>

        "Create Signer" {
            signer = PlatformSigningProvider.createSigningKey(alias) {
                ec {}
                hardware {
                    attestation {
                        this.challenge = challenge.nonce
                    }
                }
            }.getOrThrow() as Signer.Attestable<AndroidKeystoreAttestation>
        }

        "POST attestation" {
            val csr = signer.createCsr(challenge).getOrThrow()
            val result = servus.attest(csr, challenge.attestationEndpointUrl)
            result.shouldBeInstanceOf<AttestationResponse.Success>()
        }
    }
})