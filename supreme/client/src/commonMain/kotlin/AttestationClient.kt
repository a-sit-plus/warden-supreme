package at.asitplus.attestation.supreme

import at.asitplus.KmmResult
import at.asitplus.attestation.supreme.AttestationChallenge.Companion.CURRENT_VERSION
import at.asitplus.catching
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.serialNumber
import at.asitplus.signum.indispensable.jsonEncoded
import at.asitplus.signum.indispensable.pki.*
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.signum.supreme.dsl.PREFERRED
import at.asitplus.signum.supreme.os.PlatformSigningProvider
import at.asitplus.signum.supreme.sign
import at.asitplus.signum.supreme.sign.Signer
import io.ktor.client.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.statement.bodyAsChannel
import io.ktor.client.statement.HttpResponse
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.utils.io.readAvailable
import kotlinx.serialization.json.Json
import kotlin.time.Clock

/**
 * Mobile client, fetching attestation challenges and posting signed CSRs or unsigned TBS CSRs containing
 * attestation statements to an attestation verification endpoint.
 *
 * Based on a _Ktor_ [client]. Automatically installs JSON content negotiation.
 * [maxAttestationPayloadBytes] bounds challenge and response bodies before they are deserialized.
 * For testing, it is possible to provide a custom [clock] for high-level checks.
 * **Note that this clock does not affect generated attestation proofs, because those will always use the actual device clock!**
 */
class AttestationClient(
    client: HttpClient,
    private val clock: Clock = Clock.System,
    private val maxAttestationPayloadBytes: Int = WardenDefaults.DEFAULT_MAX_ATTESTATION_PAYLOAD_BYTES,
) {
    init {
        require(maxAttestationPayloadBytes > 0) { "maxAttestationPayloadBytes must be positive" }
    }

    private val client = client.config {
        install(ContentNegotiation) {
            json()
        }
        expectSuccess = true //every response needs to be 2xx, or else an exception is thrown
    }

    /**
     * Fetches a challenge from an endpoint. This is the first step in an attestation ceremony.
     *
     * The challenge endpoint is a trust boundary: its response is deserialized before the client can validate its
     * contents. Use HTTPS and configure certificate pinning on the supplied Ktor client where appropriate. A client
     * must only fetch challenges from a verifier it trusts.
     *
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
        Json.decodeFromString<AttestationChallenge>(
            client.get(endpoint).boundedPayload(maxAttestationPayloadBytes).also(::requireBoundedArrayNesting)
        ).also {
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
     * Posts an attestation proof created by [createAttestationProof]. Signed proofs send a complete PKCS#10 CSR;
     * hash-authenticated proofs send an unsigned TBS CSR. Both are encoded as DER octet streams.
     */
    @Throws(Throwable::class)
    suspend fun attest(attestationProof: AttestationProof, destination: Url) =
        Json.decodeFromString<AttestationResponse>(client.post(destination) {
            contentType(ContentType.Application.OctetStream)
            setBody(
                when (attestationProof) {
                    is AttestationProof.Signed -> attestationProof.data.encodeToDer()
                    is AttestationProof.Hashed -> attestationProof.data.encodeToDer()
                }
            )
        }.boundedPayload(maxAttestationPayloadBytes))


    @Deprecated("To be removed in Warden Supreme 1.3. Use the overload taking AttestationProof")
    @Throws(Throwable::class)
    suspend fun attest(csr: Pkcs10CertificationRequest, destination: Url) =
        attest(AttestationProof.Signed(csr), destination)
}

private suspend fun HttpResponse.boundedPayload(maxAttestationPayloadBytes: Int): String {
    val bytes = ByteArray(maxAttestationPayloadBytes + 1)
    val channel = bodyAsChannel()
    var size = 0
    while (size < bytes.size) {
        val read = channel.readAvailable(bytes, size, bytes.size - size)
        if (read <= 0) break
        size += read
    }
    require(size <= maxAttestationPayloadBytes) {
        "Attestation payload exceeds $maxAttestationPayloadBytes bytes"
    }
    return bytes.copyOf(size).decodeToString()
}

/**
 * Truly integrated attestation in a single call.
 * @throws Throwable Various errors can occur irrespective of attestation:
 * IO, accessing the platform crypto, not authenticating, etc…
 *
 * This is literally a shorthand for:
 * ```
 * val challenge = getChallenge(fetchChallengeEndpoint).getOrThrow()
 * val proof = challenge.createAttestationProof(alias) { requested -> provideValues(requested) }.getOrThrow()
 * return attest(proof, challenge.attestationEndpointUrl)
 * ```
 *
 * The challenge selects signed or hash-based authentication. [authPromptMessage] and [authPromptCancelText] apply when
 * private-key use requires authentication; hash-based authentication does not sign the TBS CSR.
 *
 * Requires the verifier to pack [KeyConstraints] into the conveyed challenge.
 *
 *
 * Usually, you'll want to use pass [AlternativeNames] into [additionalCsrExtensions], not a subject name!
 * By default, the RDN used for the TBS CSR contains [KnownOIDs.serialNumber] with the challenge nonce.
 * Hence, the values passed to this parameter containing a [KnownOIDs.serialNumber] will be overwritten.
 *
 * @param additionalCsrExtensions Certificate extensions to be requested. May be ignored by the issuer.
 *
 * @param additionalCsrAttributes Additional CSR attributes to pack into this CSR.
 * @param toBeAttestedAttributes Supplies values requested by [AttestationChallenge.toBeAttestedAttributes], in exactly
 * the same order. It is invoked once when values are requested and not invoked otherwise. Optional values may be `null`;
 * required values may not.
 *
 */
@Throws(Throwable::class)
suspend fun AttestationClient.performAttestationFlow(
    alias: String, fetchChallengeEndpoint: Url,
    authPromptMessage: String? = null,
    authPromptCancelText: String? = null,
    additionalCsrExtensions: List<X509CertificateExtension> = listOf(),
    additionalCsrAttributes: List<Pkcs10CertificationRequestAttribute> = listOf(),
    toBeAttestedAttributes: (List<AttestationChallenge.AttributeAttestationDescriptor>) -> List<Primitive>,
): AttestationResponse {
    val challenge = getChallenge(fetchChallengeEndpoint).getOrThrow()
    val proof = challenge.createAttestationProof(
        alias,
        authPromptMessage,
        authPromptCancelText,
        additionalCsrExtensions,
        additionalCsrAttributes,
        toBeAttestedAttributes
    ).getOrThrow()
    return attest(proof, challenge.attestationEndpointUrl)
}

@Deprecated("To be removed in Warden Supreme 1.3. Use the overload accepting toBeAttestedAttributes")
@Throws(Throwable::class)
suspend fun AttestationClient.performAttestationFlow(
    alias: String,
    fetchChallengeEndpoint: Url,
    authPromptMessage: String? = null,
    authPromptCancelText: String? = null,
    additionalCsrExtensions: List<X509CertificateExtension> = listOf(),
    additionalCsrAttributes: List<Pkcs10CertificationRequestAttribute> = listOf(),
): AttestationResponse {
    val challenge = getChallenge(fetchChallengeEndpoint).getOrThrow()
    require(challenge.toBeAttestedAttributes == null) {
        "The deprecated CSR-only overload cannot attest additional attributes"
    }
    require(challenge.dataAuth == DataAuthentication.Signature) {
        "The deprecated CSR-only overload requires signature data authentication"
    }
    return attest(
        challenge.createAttestationProof(
            alias,
            authPromptMessage,
            authPromptCancelText,
            additionalCsrExtensions,
            additionalCsrAttributes,
        ) { emptyList() }.getOrThrow(),
        challenge.attestationEndpointUrl,
    )
}

/**
 * Creates a signed CSR or unsigned TBS CSR from this challenge, according to [AttestationChallenge.dataAuth].
 * Key creation follows [AttestationChallenge.keyConstraints].
 * Hence, if no constraints are set, this method will always fail!
 *
 * [DataAuthentication.Signature] signs the completed TBS CSR and proves possession of the attested private key.
 * [DataAuthentication.Hash] hashes an [AttestationHashInput] containing the subject, extensions, and attributes, feeds
 * that digest into platform attestation, and returns the completed but unsigned TBS CSR. The verifier separately checks
 * that its public key is the attested key.
 *
 * Encodes the challenge's nonce into a [KnownOIDs.serialNumber] subjectName
 * and the attestation statement into a Pkcs10CertificationRequestAttribute with [AttestationChallenge.proofOID].
 * Signing may require user authentication. Hash authentication performs no CSR signing.
 *
 * Usually, you'll want to use pass [AlternativeNames] into [additionalCsrExtensions], not a subject name!
 * By default, the RDN used for this CSR will only contain [KnownOIDs.serialNumber] containing the nonce from the passed [nonce].
 * Hence, the values passed to this parameter containing a [KnownOIDs.serialNumber] will be overwritten.
 *
 * @param additionalCsrExtensions Certificate extensions to be requested. May be ignored by the issuer.
 *
 * @param additionalCsrAttributes Additional CSR attributes to pack into this CSR.
 * @param attestAttributes Supplies the requested values in order. It is invoked exactly once when
 * [AttestationChallenge.toBeAttestedAttributes] is present and is not invoked otherwise.
 *
 * @return [AttestationProof.Signed] for [DataAuthentication.Signature], or
 * [AttestationProof.Hashed] for [DataAuthentication.Hash].
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
    attestAttributes: (List<AttestationChallenge.AttributeAttestationDescriptor>) -> List<Primitive>,
): KmmResult<AttestationProof> {

    val constraints = keyConstraints
        ?: throw IllegalArgumentException("No algorithm specified. Refusing to automatically create an attested key")
    val params = constraints.algorithmParameters
    val protectionParameters = constraints.keyProtection
    val deviceName = genericDeviceNameOID?.let { getDeviceName() }
    val otherAttributes = toBeAttestedAttributes?.let { requested ->
        attestAttributes(requested.attributes).also {
            require(it.size == requested.attributes.size) {
                "Expected ${requested.attributes.size} attested attributes, got ${it.size}"
            }
        }.toSequence()
    }
    val additionalAttributes = additionalCsrAttributes + listOfNotNull(
        genericDeviceNameOID?.let {
            Pkcs10CertificationRequestAttribute(it, Asn1String.UTF8(deviceName!!).encodeToTlv())
        },
        toBeAttestedAttributes?.let {
            Pkcs10CertificationRequestAttribute(it.oid, otherAttributes!!)
        },
    )
    val hashInput = AttestationHashInput(
        subjectName = csrSubjectName(),
        extensions = additionalCsrExtensions,
        attributes = additionalAttributes,
    )


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
            backing = PREFERRED
            attestation {
                challenge = when (val authentication = dataAuth) {
                    DataAuthentication.Signature -> nonce
                    is DataAuthentication.Hash -> authentication.algorithm.digest(hashInput.encodeToDer())
                }
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

    val signer = PlatformSigningProvider.getSignerForKey(alias) {
        unlockPrompt {
            authPromptMessage?.let { message = it }
            authPromptCancelText?.let { cancelText = it }
        }
    }.getOrThrow()
    val tbsCsr = signer.createTbsCsr(this, hashInput).getOrThrow()

    return catching {
        when (dataAuth) {
            DataAuthentication.Signature ->
                AttestationProof.Signed(signer.sign(tbsCsr).getOrThrow())

            is DataAuthentication.Hash -> AttestationProof.Hashed(tbsCsr)
        }
    }
}

@Deprecated("To be removed in Warden Supreme 1.3. Use the overload accepting attestAttributes")
suspend fun AttestationChallenge.createAttestationProof(
    alias: String,
    authPromptMessage: String? = null,
    authPromptCancelText: String? = null,
    additionalCsrExtensions: List<X509CertificateExtension> = listOf(),
    additionalCsrAttributes: List<Pkcs10CertificationRequestAttribute> = listOf(),
): KmmResult<Pkcs10CertificationRequest> = catching {
    require(toBeAttestedAttributes == null) {
        "The deprecated CSR-only overload cannot attest additional attributes"
    }
    require(dataAuth == DataAuthentication.Signature) {
        "The deprecated CSR-only overload requires signature data authentication"
    }
    (createAttestationProof(
        alias,
        authPromptMessage,
        authPromptCancelText,
        additionalCsrExtensions,
        additionalCsrAttributes,
    ) { emptyList() }.getOrThrow() as AttestationProof.Signed).data
}

/**
 * Creates a signed CSR from an attestable signer. This is the low-level signature-authentication path and always proves
 * possession of the private key; use [createAttestationProof] to follow a challenge-selected authentication mode.
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
    additionalAttributes: List<Pkcs10CertificationRequestAttribute> = listOf(),
): KmmResult<Pkcs10CertificationRequest> = catching {
    sign(createTbsCsr(challenge, subjectName, additionalExtensions, additionalAttributes).getOrThrow()).getOrThrow()
}

/**
 * Creates a TBS CSR containing this signer's public key and attestation statement. This overload derives the subject,
 * extensions, and attributes directly from [challenge] and the supplied additions.
 */
fun Signer.Attestable<*>.createTbsCsr(
    challenge: AttestationChallenge,
    subjectName: List<RelativeDistinguishedName> = listOf(),
    additionalExtensions: List<X509CertificateExtension> = listOf(),
    additionalAttributes: List<Pkcs10CertificationRequestAttribute> = listOf(),
): KmmResult<TbsCertificationRequest> = catching {
    createTbsCsr(
        challenge,
        AttestationHashInput(
            subjectName = challenge.csrSubjectName(subjectName),
            extensions = additionalExtensions,
            attributes = additionalAttributes,
        ),
    ).getOrThrow()
}

/**
 * Completes [hashInput] with this signer's public key and attestation statement. The same conversion is used for signed
 * and hash-authenticated proofs; callers decide separately whether to sign the result.
 */
fun Signer.Attestable<*>.createTbsCsr(
    challenge: AttestationChallenge,
    hashInput: AttestationHashInput,
): KmmResult<TbsCertificationRequest> = catching {
    val attestation = requireNotNull(attestation) { "No attestation statement present instance found" }
    hashInput.toTbsCsr(
        publicKey,
        Pkcs10CertificationRequestAttribute(
            challenge.proofOID,
            Asn1String.UTF8(attestation.jsonEncoded).encodeToTlv(),
        ),
    )
}

private fun AttestationChallenge.csrSubjectName(
    subjectName: List<RelativeDistinguishedName> = emptyList(),
) = subjectName.map { name ->
    RelativeDistinguishedName(name.attrsAndValues.filterNot { value -> value.oid == KnownOIDs.serialNumber })
} + RelativeDistinguishedName(getRdnSerialNumber())

/**
 * convenience shorthand to parse the attestation POST endpoint as a URL
 */
val AttestationChallenge.attestationEndpointUrl: Url get() = Url(attestationEndpoint);

internal expect fun getDeviceName(): String
