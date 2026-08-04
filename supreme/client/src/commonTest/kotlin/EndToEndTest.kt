import at.asitplus.attestation.supreme.*
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.pki.leaf
import at.asitplus.signum.supreme.os.PlatformSigningProvider
import at.asitplus.test.Target
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.datetime.LocalDate
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

val ENDPOINT_CHALLENGE = "http://10.0.2.2:8080/api/v1/challenge"
val ENDPOINT_SHUTDOWN = "http://10.0.2.2:8080/shutdown"

val ALIAS = "ALIAS"

private data class AuthenticationScenario(
    val name: String,
    val authentication: DataAuthentication,
    val attributes: List<Primitive>?,
    val succeeds: Boolean = true,
)

private val authenticationScenarios = listOf(
    AuthenticationScenario("signed-no-attributes", DataAuthentication.Signature, null),
    AuthenticationScenario("hashed-no-attributes", DataAuthentication.Hash(Digest.SHA256), null),
    AuthenticationScenario("signed-optional-present", DataAuthentication.Signature, listOf("required", 42)),
    AuthenticationScenario("signed-optional-omitted", DataAuthentication.Signature, listOf("required", null)),
    AuthenticationScenario("hashed-optional-present", DataAuthentication.Hash(Digest.SHA256), listOf("required", 42)),
    AuthenticationScenario("hashed-optional-omitted", DataAuthentication.Hash(Digest.SHA256), listOf("required", null)),
    AuthenticationScenario("signed-required-omitted", DataAuthentication.Signature, listOf(null, 42), false),
    AuthenticationScenario("hashed-required-omitted", DataAuthentication.Hash(Digest.SHA256), listOf(null, 42), false),
    AuthenticationScenario("signed-all-omitted", DataAuthentication.Signature, listOf(null, null), false),
    AuthenticationScenario("hashed-all-omitted", DataAuthentication.Hash(Digest.SHA256), listOf(null, null), false),
)

val EndToEndTest by matrixSuite {
    //This test lives here due to IDEA not recognizing androidDevicTest sources being wired to commonTest
    //to not make ios fail, we guard it here
    if (Target.current == Target.ANDROID_ART) {

        test("endToEnd") {
            PlatformSigningProvider.deleteSigningKey(ALIAS)
            val client = AttestationClient(HttpClient(), FixedTimeClock(2025u,1u,10u))

            val result = client.performAttestationFlow(ALIAS,Url(ENDPOINT_CHALLENGE))
            val clue =
                if (result is AttestationResponse.Failure)
                    result.kind.name + ": " + (result.explanation ?: "FAIL")
                else ""
            withClue(clue) {
                result.shouldBeInstanceOf<AttestationResponse.Success>()
                withClue("Cert leaf pub key is the original attested key") {
                    result.certificateChain.leaf.decodedPublicKey.getOrThrow() shouldBe PlatformSigningProvider.getSignerForKey(
                        ALIAS
                    ).getOrThrow().publicKey
                }
            }

        }

        authenticationScenarios.forEachIndexed { index, scenario ->
            test(scenario.name) {
                val alias = "E2E_AUTH_$index"
                PlatformSigningProvider.deleteSigningKey(alias)
                val client = AttestationClient(HttpClient(), FixedTimeClock(2025u, 1u, 10u))
                val challenge = client.getChallenge(
                    Url("$ENDPOINT_CHALLENGE/${scenario.name}")
                ).getOrThrow()
                challenge.dataAuth shouldBe scenario.authentication

                val proof = challenge.createAttestationProof(alias) { requested ->
                    requested shouldBe listOf(
                        AttestationChallenge.ToBeAttestedAttribute("required", PrimitiveType.STRING),
                        AttestationChallenge.ToBeAttestedAttribute("optional", PrimitiveType.INT, required = false),
                    )
                    requireNotNull(scenario.attributes)
                }.getOrThrow()

                when (scenario.authentication) {
                    DataAuthentication.Signature -> proof.shouldBeInstanceOf<AttestationProof.Signed>()
                    is DataAuthentication.Hash -> proof.shouldBeInstanceOf<AttestationProof.Hashed>()
                }

                val result = client.attest(proof, challenge.attestationEndpointUrl)
                if (scenario.succeeds) {
                    result.shouldBeInstanceOf<AttestationResponse.Success>().also { success ->
                        success.certificateChain.leaf.decodedPublicKey.getOrThrow() shouldBe
                                PlatformSigningProvider.getSignerForKey(alias).getOrThrow().publicKey
                    }
                } else {
                    result.shouldBeInstanceOf<AttestationResponse.Failure>().kind shouldBe
                            AttestationResponse.Failure.Type.CONTENT
                }
            }
        }


        test("shutdown") {
            HttpClient().get(ENDPOINT_SHUTDOWN)
        }
    } else test("NOOP") {

    }
}

private class FixedTimeClock(private var epochMilliseconds: Long) : Clock {
    constructor(instant: Instant) : this(instant.toEpochMilliseconds())
    constructor(yyyy: UInt, mm: UInt, dd: UInt) : this(
        LocalDate(yyyy.toInt(), mm.toInt(), dd.toInt()).toEpochDays().days.inWholeMilliseconds
    )

    fun offsetBy(duration: Duration) {
        epochMilliseconds += duration.inWholeMilliseconds
    }

    override fun now() = Instant.fromEpochMilliseconds(epochMilliseconds)
}
