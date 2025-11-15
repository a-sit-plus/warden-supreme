package at.asitplus.attestation.supreme

import at.asitplus.KmmResult
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
 */
class AttestationClient(client: HttpClient) {
    private val client = client.config {
        install(ContentNegotiation) {
            json()
        }
        expectSuccess = true //every response needs to be 2xx, or else an exception is thrown
    }

    /**
     * Fetches a challenge from an endpoint. This is the first step in an attestation ceremony.
     * This will fail if the system time is off too much:
     *  * [AttestationChallenge.validUntil] is earlier than the local system clock
     *  * [AttestationChallenge.issuedAt] is later than the local system clock
     *
     * The reason for the second constraint is the simple fact that if the backend's clock lags behind the local system clock
     * (i.e., challenge issuing time is after [Clock.System.now]), certificate chain validation will fail, due to the
     * leaf certificate's `notBefore` being in the future from the backend's point of view.
     *
     * The first contraint simply fails early for challenges that will be rejected by the backend anyhow. Since [AttestationChallenge.validUntil] may be `null`,
     * this check is only performed if the challenge indicates any validity.
     */
    suspend fun getChallenge(endpoint: Url): KmmResult<AttestationChallenge> = catching {
        client.get(endpoint).body<AttestationChallenge>().also {
            val now = Clock.System.now()
            if (it.validUntil?.let { it < now } == true || it.issuedAt > now) throw IllegalStateException(
                "System time off: issuedAt: ${it.issuedAt}, validUntil: ${it.validUntil}, local system time: $now"
            )
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
 * Creates a signed CSR from a received [AttestationChallenge] according to [AttestationChallenge.keyConstraints].
 * Hence, if no constraints are set, this method will always fail!
 *
 * Encodes the challenge's nonce into a [KnownOIDs.serialNumber] subjectName
 * and the attestation statement into a Pkcs10CertificationRequestAttribute with [AttestationChallenge.proofOID].
 * Since this operation prepares and directly signs the CSR, it may require user authentication.
 */
suspend fun AttestationChallenge.createAttestationProof(
    /**
     * The alias to assign to the newly created signer. Must not exist!
     */
    alias: String,
): KmmResult<Pkcs10CertificationRequest> {


    val params = keyConstraints?.algorithmParameters
        ?: throw IllegalArgumentException("No algorithm specified. Refusing to automatically create an attested key")
    val protectionParameters = keyConstraints?.keyProtection
    val signer = PlatformSigningProvider.createSigningKey(alias) {

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
    val additionalAttributes = if (includeGenericDeviceName) listOf(
        Pkcs10CertificationRequestAttribute(
            WardenDefaults.OIDs.DEVICE_NAME,
            Asn1String.UTF8(getDeviceName()).encodeToTlv()
        )
    ) else listOf()
    return signer.createCsr(this, additionalAttributes = additionalAttributes)
}

/**
 * Creates a signed CSR from an attestable signer.
 * Encodes the challenge's nonce into a [KnownOIDs.serialNumber] subjectName
 * and the attestation statement into a Pkcs10CertificationRequestAttribute with [AttestationChallenge.proofOID].
 * Since this operation prepares and directly signs the CSR, it may require user authentication
 */
suspend fun Signer.Attestable<*>.createCsr(
    challenge: AttestationChallenge,
    /**
     * The subject name, if required.
     * Usually, you'll want to use pass [AlternativeNames] into [additionalExtensions], not a subject name!
     * By default, the RDN used for this CSR will only contain [KnownOIDs.serialNumber] containing the nonce from the passed [challenge].
     * Hence, the valued passed to this parameter containing a [KnownOIDs.serialNumber] will be overwritten.
     */
    subjectName: List<RelativeDistinguishedName> = listOf(),

    /**
     * Certificate extensions to be requested. May be ignored by the issuer.
     */
    additionalExtensions: List<X509CertificateExtension> = listOf(),

    /**
     * Additional CSR attributes to pack into this CSR.
     */
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