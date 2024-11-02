package at.asitplus.attestation.supreme

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.jsonEncoded
import at.asitplus.signum.indispensable.pki.*
import at.asitplus.signum.supreme.sign
import at.asitplus.signum.supreme.sign.Signer
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.datetime.Clock

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
     * Fetches a challenges from an endpoint. This is the first step in an attestation ceremony.
     */
    suspend fun getChallenge(endpoint: Url) = catching {
        client.get(endpoint).body<AttestationChallenge>().also {
            if (it.validUntil?.let { it < Clock.System.now() } == true || it.issuedAt > Clock.System.now()) throw IllegalStateException(
                "System time off!"
            )
        }
    }

    /**
     * Posts a [csr] containing an attestation challenge, as created by [createCsr].
     */
    suspend fun attest(csr: Pkcs10CertificationRequest, destination: Url) =
        client.post(destination) {
            contentType(ContentType.Application.OctetStream)
            setBody(csr.encodeToDer())
        }.body<AttestationResponse>()
}

/**
 * Creates a signed CSR from an attestable signer.
 * Encodes the challenge's nonce into a [KnownOIDs.serialNumber] subjectName
 * and the attestation statement into a Pkcs10CertificationRequestAttribute with [attestationOID].
 * Since this operation prepares and directly signs the CSR, it may require user authentication
 */
suspend fun Signer.Attestable<*>.createCsr(
    challenge: AttestationChallenge,
    /**
     * The subject name, if required.
     * Usually, you'll want to use pass [AlternativeNames] into [additionalExtensions], not a subject name!
     * By default, the RDN used for this CSR will only contain [KnownOIDs.serialNumber] containing the nonce from the passed [challenge].
     * Hence, the valued passed to this parameter MUST NOT contain a [KnownOIDs.serialNumber].
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

