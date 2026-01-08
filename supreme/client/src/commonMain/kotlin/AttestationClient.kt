package at.asitplus.attestation.supreme

import at.asitplus.KmmResult
import at.asitplus.attestation.supreme.AttestationChallenge.Companion.CURRENT_VERSION
import at.asitplus.catching
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.serialNumber
import at.asitplus.signum.indispensable.jsonEncoded
import at.asitplus.signum.indispensable.pki.*
import at.asitplus.signum.supreme.os.PlatformSigningProvider
import at.asitplus.signum.supreme.sign
import at.asitplus.signum.supreme.sign.Signer
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlin.time.Clock

/**
 * Mobile client, fetching attestation challenges and posting CSRs containing
 * attestation statements to an attestation verification endpoint.
 *
 * Based on a _Ktor_ [client]. Automatically installs JSON content negotiation.
 * For testing, it is possible to provide a custom [clock] for high-level checks.
 * **Note that this clock does not affect generated attestation proofs, because those will always use the actual device clock!**
 */
class AttestationClient(client: HttpClient, private val clock: Clock = Clock.System) {
    private val client = client.config {
        install(ContentNegotiation) {
            json()
        }
        expectSuccess = true //every response needs to be 2xx, or else an exception is thrown
    }

    /**
     * Fetches a challenge from an endpoint. This is the first step in an attestation ceremony.
     * This will fail if the system time is off too much:
     *  * [AttestationChallenge.validUntil] is earlier than the local clock
     *  * [AttestationChallenge.issuedAt] is later than the local clock
     *
     *  This will also fail when a challenge of a newer version was received
     *
     * The reason for the second constraint is the simple fact that if the back-end's clock lags behind the local clock
     * (i.e., challenge issuing time is after [clock]`.now`), certificate chain validation will fail, due to the
     * leaf certificate's `notBefore` being in the future from the back-end's point of view.
     *
     * The first contraint simply fails early for challenges that will be rejected by the back-end anyhow. Since [AttestationChallenge.validUntil] may be `null`,
     * this check is only performed if the challenge indicates any validity.
     */
    suspend fun getChallenge(endpoint: Url): KmmResult<AttestationChallenge> = catching {
        client.get(endpoint).body<AttestationChallenge>().also {
            val now = clock.now()
            if (it.validUntil < now || it.issuedAt > now) throw IllegalStateException(
                "System time off: issuedAt: ${it.issuedAt}, validUntil: ${it.validUntil}, local system time: $now"
            )
            it.version?.let { ver ->
                if (ver > CURRENT_VERSION) throw IllegalArgumentException("Received AttestationChallenge version ${it.version} is newer than locally supported version $CURRENT_VERSION")
                //TODO once needed: different logic based on version
            }
        }
    }

    /**
     * Posts a [csr] containing an attestation challenge, as created by [createAttestationProof].
     * @throws Throwable for any IO/low-level errors. Attestation failures are **not** thrown but encoded into the [AttestationResponse]!
     */
    @Throws(Throwable::class)
    suspend fun attest(csr: Pkcs10CertificationRequest, destination: Url) =
        client.post(destination) {
            contentType(ContentType.Application.OctetStream)
            setBody(csr.encodeToDer())
        }.body<AttestationResponse>()
}

/**
 * Truly integrated attestation in a single call.
 * @throws Throwable Various errors can occur irrespective of attestation:
 * IO, accessing the platform crypto, not authenticating, etc…
 *
 * This is literally a shorthand for:
 * ```
 * val challenge = getChallenge(fetchChallengeEndpoint).getOrThrow()
 * val csr = challenge.createAttestationProof(alias).getOrThrow()
 * return attest(csr, challenge.attestationEndpointUrl)
 * ```
 *
 * It is possible to specify [authPromptMessage] and [authPromptCancelText] for when key usage (i.e. signing)
 * requires authentication.
 *
 * Requires the verifier to pack [KeyConstraints] into the conveyed challenge.
 *
 *
 * Usually, you'll want to use pass [AlternativeNames] into [additionalCsrExtensions], not a subject name!
 * By default, the RDN used for this CSR will only contain [KnownOIDs.serialNumber] containing the nonce from the passed [challenge].
 * Hence, the values passed to this parameter containing a [KnownOIDs.serialNumber] will be overwritten.
 *
 * @param additionalCsrExtensions Certificate extensions to be requested. May be ignored by the issuer.
 *
 * @param additionalCsrAttributes Additional CSR attributes to pack into this CSR.
 *
 */
@Throws(Throwable::class)
suspend fun AttestationClient.performAttestationFlow(
    alias: String, fetchChallengeEndpoint: Url,
    authPromptMessage: String? = null,
    authPromptCancelText: String? = null,
    additionalCsrExtensions: List<X509CertificateExtension> = listOf(),
    additionalCsrAttributes: List<Pkcs10CertificationRequestAttribute> = listOf(),
): AttestationResponse {
    val challenge = getChallenge(fetchChallengeEndpoint).getOrThrow()
    val csr = challenge.createAttestationProof(
        alias,
        authPromptMessage,
        authPromptCancelText,
        additionalCsrExtensions,
        additionalCsrAttributes
    ).getOrThrow()
    return attest(csr, challenge.attestationEndpointUrl)
}

/**
 * Creates a signed CSR from a received [AttestationChallenge] according to [AttestationChallenge.keyConstraints].
 * Hence, if no constraints are set, this method will always fail!
 *
 * It is possible to specify [authPromptMessage] and [authPromptCancelText] for when key usage (i.e. signing)
 * requires authentication.
 *
 * Encodes the challenge's nonce into a [KnownOIDs.serialNumber] subjectName
 * and the attestation statement into a Pkcs10CertificationRequestAttribute with [AttestationChallenge.proofOID].
 * Since this operation prepares and directly signs the CSR, it may require user authentication.
 *
 * Usually, you'll want to use pass [AlternativeNames] into [additionalCsrExtensions], not a subject name!
 * By default, the RDN used for this CSR will only contain [KnownOIDs.serialNumber] containing the nonce from the passed [challenge].
 * Hence, the values passed to this parameter containing a [KnownOIDs.serialNumber] will be overwritten.
 *
 * @param additionalCsrExtensions Certificate extensions to be requested. May be ignored by the issuer.
 *
 * @param additionalCsrAttributes Additional CSR attributes to pack into this CSR.
 */
suspend fun AttestationChallenge.createAttestationProof(
    /**
     * The alias to assign to the newly created signer. Must not exist!
     */
    alias: String,
    authPromptMessage: String? = null,
    authPromptCancelText: String? = null,
    additionalCsrExtensions: List<X509CertificateExtension> = listOf(),
    additionalCsrAttributes: List<Pkcs10CertificationRequestAttribute> = listOf(),
): KmmResult<Pkcs10CertificationRequest> {


    val params = keyConstraints?.algorithmParameters
        ?: throw IllegalArgumentException("No algorithm specified. Refusing to automatically create an attested key")
    val protectionParameters = keyConstraints?.keyProtection
    PlatformSigningProvider.createSigningKey(alias) {
        when (params) {
            is KeyConstraints.AlgorithmParameters.EC -> ec {
                curve = params.curve
                digests = params.digests

                purposes {
                    signing = params.allowSigning
                    keyAgreement = params.allowKeyAgreement
                }

            }

            is KeyConstraints.AlgorithmParameters.RSA -> rsa {
                paddings = params.paddings
                digests = params.digests
                bits = params.keySize.bits.toInt()
                purposes {
                    signing = params.allowSigning
                    decrypting = params.allowDecrypting
                }
            }
        }
        hardware {
            attestation {
                challenge = this@createAttestationProof.nonce
            }
            protectionParameters?.let {
                protection {
                    it.timeout?.let { timeout = it }
                    factors {
                        it.biometry?.let { biometry = it }
                        it.deviceLock?.let { deviceLock = it }
                        it.allowNewBiometricFactors?.let { biometryWithNewFactors = it }
                    }
                }
            }
        }
    }.getOrThrow()
    val additionalAttributes = genericDeviceNameOID?.let { deviceNameOID ->
        additionalCsrAttributes +
                Pkcs10CertificationRequestAttribute(
                    deviceNameOID,
                    Asn1String.UTF8(getDeviceName()).encodeToTlv()
                )

    } ?: additionalCsrAttributes
    val signer = PlatformSigningProvider.getSignerForKey(alias) {
        unlockPrompt {
            authPromptMessage?.let { message = it }
            authPromptCancelText?.let { cancelText = it }
        }
    }.getOrThrow()
    return signer.createCsr(
        this,
        additionalExtensions = additionalCsrExtensions,
        additionalAttributes = additionalAttributes
    )
}

/**
 * Creates a signed CSR from an attestable signer.
 * Encodes the challenge's nonce into a [KnownOIDs.serialNumber] subjectName
 * and the attestation statement into a Pkcs10CertificationRequestAttribute with [AttestationChallenge.proofOID].
 * Since this operation prepares and directly signs the CSR, it may require user authentication.
 *
 * @param subjectName The subject name, if required.
 * Usually, you'll want to use pass [AlternativeNames] into [additionalExtensions], not a subject name!
 * By default, the RDN used for this CSR will only contain [KnownOIDs.serialNumber] containing the nonce from the passed [challenge].
 * Hence, the values passed to this parameter containing a [KnownOIDs.serialNumber] will be overwritten.
 *
 * @param additionalExtensions Certificate extensions to be requested. May be ignored by the issuer.
 *
 * @param additionalAttributes Additional CSR attributes to pack into this CSR.
 */
suspend fun Signer.Attestable<*>.createCsr(
    challenge: AttestationChallenge,
    subjectName: List<RelativeDistinguishedName> = listOf(),
    additionalExtensions: List<X509CertificateExtension> = listOf(),
    additionalAttributes: List<Pkcs10CertificationRequestAttribute> = listOf()
): KmmResult<Pkcs10CertificationRequest> =
    attestation?.let { attestation ->
        sign(
            TbsCertificationRequest(
                subjectName = subjectName.map { name ->
                    RelativeDistinguishedName(name.attrsAndValues.filterNot { value -> value.oid == KnownOIDs.serialNumber })
                } + RelativeDistinguishedName(challenge.getRdnSerialNumber()),
                publicKey = publicKey,
                attributes = additionalAttributes + Pkcs10CertificationRequestAttribute(
                    challenge.proofOID,
                    Asn1String.UTF8(attestation.jsonEncoded).encodeToTlv()
                ),
                extensions = additionalExtensions
            ))
    } ?: KmmResult.failure(IllegalStateException("No attestation statement present instance found"))

/**
 * convenience shorthand to parse the attestation POST endpoint as a URL
 */
val AttestationChallenge.attestationEndpointUrl: Url get() = Url(attestationEndpoint);

expect internal fun getDeviceName(): String