package at.asitplus.attestation.supreme

import at.asitplus.KmmResult
import at.asitplus.attestation.*
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.attestation.supreme.AttestationResponse.Failure
import at.asitplus.attestation.supreme.AttestationResponse.Failure.Type
import at.asitplus.attestation.supreme.PreAttestationError.ChallengeVerification
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequest
import at.asitplus.signum.indispensable.pki.TbsCertificationRequest
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.signum.supreme.hash.digest
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.datetime.TimeZone
import org.kotlincrypto.random.CryptoRand
import java.security.PublicKey
import java.security.Signature
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime

private val extensionRequestOid = ObjectIdentifier("1.2.840.113549.1.9.14")

/**
 * Verifies attestation statements and issues certificates on success.
 * Expects a preconfigured [Makoto] instance defining which apps and devices are considered trustworthy.
 *
 * [attestationProofOID] identifies the TBS CSR attribute carrying the attestation statement. It defaults to
 * [WardenDefaults.OIDs.ATTESTATION_PROOF]. [dataAuth] selects the default authentication mode for issued challenges:
 * signed PKCS#10 with proof of possession, or hash-bound unsigned TBS CSR without proof of possession.
 * [attestableAttributes] optionally requests ordered client-provided values which are encoded into the TBS CSR and
 * authenticated by the selected mode.
 * When [defaultKeyConstraints] is specified, all issued challenges will automatically convey this, unless overridden.
 * **Note that key constraints cannot be reliably enforced** due to technical client limitations. Not all platforms can restrict key usage and properties!
 * Still, Warden Supreme's client will respect the key constraints and create keys as specified.
 *
 * [genericDeviceNameOID] indicates whether to include a generic make and model (such as "Google Pixel 8", or "iPhone 16") with the attestation proof.
 * On its own, this is **not the device's nickname and therefore cannot identify a person in its own**.
 * Defaults to [WardenDefaults.OIDs.DEVICE_NAME] as it is very useful technical, **non-personally-identifying data**.
 * Can be set to `null` to not include device names.
 *
 * The [nonceGenerator]'s responsibility is to generate nonces to ensure freshness of issues challenges. Defaults to [WardenDefaults.nonceGenerator],
 * which generates secure, random 64-byte nonces
 *
 * [nonceValidity] indicates how long issued nonces remain valid. This defaults to the maximum of the passed [makoto]'s
 * [IosAttestationConfiguration.attestationStatementValiditySeconds] and [AndroidAttestationConfiguration.attestationStatementValiditySeconds].
 *
 */

class AttestationVerifier
@Throws(AttestationException.Configuration::class, IllegalArgumentException::class)
constructor(
    val makoto: Makoto,
    val attestationProofOID: ObjectIdentifier = WardenDefaults.OIDs.ATTESTATION_PROOF,
    val genericDeviceNameOID: ObjectIdentifier? = WardenDefaults.OIDs.DEVICE_NAME,
    val defaultKeyConstraints: KeyConstraints? = WardenDefaults.KeyConstraints.p256Signer,
    val nonceValidity: Duration = makoto.longestValidityDuration
        ?: IosAttestationConfiguration.DEFAULT_VALIDITY_SECONDS.seconds,
    val attestableAttributes: AttestationChallenge.AttestableAttributes? = null,
    val dataAuth: DataAuthentication = DataAuthentication.Signature,
    private val nonceGenerator: NonceGenerator = WardenDefaults.nonceGenerator,
    /*internal for testing*/
    internal val challengeValidator: ChallengeValidator = InMemoryChallengeCache(
        makoto.clock,
        -makoto.verificationTimeOffset
    ),
) {

    @Deprecated(
        "Use `SupremeConfiguration` instead. To be removed in 1.1 due to inherent footguns",
        level = DeprecationLevel.ERROR
    )
    @OptIn(ExperimentalTime::class)
    @Throws(AttestationException.Configuration::class, IllegalArgumentException::class)
    constructor(
        androidAttestationConfiguration: AndroidAttestationConfiguration,
        iosAttestationConfiguration: IosAttestationConfiguration,
        attestationProofOID: ObjectIdentifier = WardenDefaults.OIDs.ATTESTATION_PROOF,
        genericDeviceNameOID: ObjectIdentifier? = WardenDefaults.OIDs.DEVICE_NAME,
        clock: Clock = Clock.System,
        verificationTimeOffset: Duration = Makoto.DEFAULT_TIME_OFFSET,
        defaultKeyConstraints: KeyConstraints? = WardenDefaults.KeyConstraints.p256Signer,
        nonceValidity: Duration = Makoto.longestDuration(
            iosAttestationConfiguration.attestationStatementValiditySeconds,
            androidAttestationConfiguration.attestationStatementValiditySeconds
        ),
        attestableAttributes: AttestationChallenge.AttestableAttributes? = null,
        dataAuth: DataAuthentication = DataAuthentication.Signature,
        nonceGenerator: NonceGenerator = suspend { CryptoRand.nextBytes(ByteArray(64)) },
        challengeValidator: ChallengeValidator = InMemoryChallengeCache(clock, -verificationTimeOffset),
    ) : this(
        Makoto(androidAttestationConfiguration, iosAttestationConfiguration, clock, verificationTimeOffset),
        attestationProofOID,
        genericDeviceNameOID,
        defaultKeyConstraints,
        nonceValidity,
        attestableAttributes,
        dataAuth,
        nonceGenerator,
        challengeValidator,
    )

    /**
     * Issues a new attestation challenge using a nonce generated by [nonceGenerator], valid for [nonceValidity], and
     * expecting an attestation proof to be `HTTP POST`ed to [postEndpoint]. The response is a signed CSR or unsigned TBS
     * CSR according to [dataAuth].
     * It is possible, to pass a [timeZone], but this is purely informational and is not fed into validity checks.
     *
     * Specify [keyConstraints] to communicate to the type of key and its properties to the client, for automatic key creation. Defaults to [defaultKeyConstraints].
     * [attestableAttributes] requests ordered client-provided values; [dataAuth] determines how the resulting TBS CSR is
     * authenticated. Both default to the verifier-wide settings and may be overridden per challenge.
     *
     * Note that the inverse of [Makoto.verificationTimeOffset] is added to the nonce validity period to account for clock drift between clients and server.
     * Why the inverse? Because clients check validity against their local clocks, reversing their relative view of the server time offset.
     *
     * **Note that the [challengeValidator] needs to account for this inverse view! The default [InMemoryChallengeCache] already does that.**
     *
     * The issued challenge nonce is sensitive replay-protection material. Treat it as a bearer value for the lifetime of
     * the challenge: do not log it, do not expose it across sessions or callers, serve it only over protected transport,
     * and keep caller/session binding and rate limiting in the surrounding HTTP layer if your service needs it.
     *
     * @throws Throwable For example, [InMemoryChallengeCache.ChallengeCacheFullException] is thrown if the default in-memory cache is full. Custom
     * [ChallengeValidator] implementations may throw their own operational exceptions from [ChallengeValidator.store].
     */
    @Throws(Throwable::class)
    suspend fun issueChallenge(
        postEndpoint: String,
        timeZone: TimeZone? = null,
        keyConstraints: KeyConstraints? = defaultKeyConstraints,
        attestableAttributes: AttestationChallenge.AttestableAttributes? = this.attestableAttributes,
        dataAuth: DataAuthentication = this.dataAuth,
    ) = AttestationChallenge(
        issuedAt = makoto.clock.now() - makoto.verificationTimeOffset,
        validity = nonceValidity,
        timeZone = timeZone,
        nonce = nonceGenerator(),
        attestationEndpoint = postEndpoint,
        proofOID = attestationProofOID,
        genericDeviceNameOID = genericDeviceNameOID,
        keyConstraints = keyConstraints,
        attestableAttributes = attestableAttributes,
        dataAuth = dataAuth,
    ).also { challengeValidator.store(it) }


    /**
     * Verifies a received signed CSR. This compatibility overload always uses [DataAuthentication.Signature]:
     * * Validates nonce contained in the [csr] against the [challengeValidator]
     * * extracts the attestation statement from the [csr]
     * * calls upon [makoto] for key and app attestation based on the extracted attestation statement
     * * verifies the [csr] signature against the contained public key
     *
     * Iff all verifications succeed, [certificateIssuer] is invoked and the resulting certificate chain
     * is returned as an [AttestationResponse.Success].
     *
     * [onPreAttestationError] allows side-effect-free investigating/logging/handling high-level errors and preparing error details for the client
     * This comprises
     * * errors in signing a binding certificate,
     * * issues trying to extract the challenge from the CSR
     * * challenge validation errors
     * * client-data authentication, structure, binding, key, and requested-attribute validation errors
     *
     * [onChallengeValidated] allows side-effect-free investigating/logging/handling of validated challenges.
     * Includes the CSR from the client.
     *
     * [onAttestationError] allows side-effect-free investigating attestation statement verification errors.
     * Gives you not only the Attestation error, but also a ready-made [WardenDebugAttestationStatement].
     * Those are essentially attestation statements received from the client that do not
     * comply with the configured attestation policy (package identifier, bootloader lock state, …).
     * In case the CSR signature is invalid, this callback is also invoked.
     *
     * [onAttestationSuccess] allows side-effect-free operations on successful attestation statement verification.
     * Logging and/or collecting numbers for statistical analysis comes to mind.
     *
     * [additionalVerifications] allows to tighten attestation constraints even more. If any custom checks fail, it should return an
     * [AttestationResponse.Failure], on success it should return null. The reason for this design is to allow additional checks to define their own semantics
     * for specific failure reasons. It *should* not throw (but should an exception bubble up, it will be mapped to an internal error).
     * Don't make your checks throw, unless you want internal errors to hit the end-users.
     *
     * Should any verification step fail, an [AttestationResponse.Failure] is returned.
     *
     * Any exception thrown by the observation callback lambdas is ignored (treated as if the callback were a NOOP).
     * [additionalVerifications] is policy logic, not an observation callback, so exceptions from it cause an internal failure to be sent as response.
     */
    @Deprecated("Replace with forward-compatible variant taking AttestationProof")
    suspend fun verifyAttestation(
        csr: Pkcs10CertificationRequest,
        onChallengeValidated: suspend AttestationChallenge.(Pkcs10CertificationRequest) -> Unit = { },
        onPreAttestationError: suspend PreAttestationError.() -> String? = { null },
        onAttestationError: suspend AttestationResult.Error.(debugInfo: WardenDebugAttestationStatement) -> String? = { null },
        onAttestationSuccess: suspend AttestationResult.Verified.(CryptoPublicKey) -> Unit = { },
        additionalVerifications: suspend AttestationChallenge.(Pkcs10CertificationRequest, AttestationResult.Verified) -> AttestationResponse.Failure? = { _, _ -> null },
        certificateIssuer: CertificateIssuer,
    ): AttestationResponse = verifyAttestation(
        attestationProof = AttestationProof.Signed(csr),
        onChallengeValidated = { onChallengeValidated(csr) },
        onPreAttestationError = {
            onPreAttestationError(
                if (this is PreAttestationError.AugmentedAttestationStatementExtraction)
                    PreAttestationError.AttestationStatementExtraction(throwable, csr)
                else this
            )
        },
        onAttestationError = onAttestationError,
        onAttestationSuccess = onAttestationSuccess,
        additionalVerifications = { _, result -> additionalVerifications(csr, result) },
        certificateIssuer = { certificateIssuer(csr) },
    )

    /**
     * Verifies a signed CSR or hash-authenticated unsigned TBS CSR.
     *
     * The transport shape must match the authentication method in the validated challenge. The verifier checks
     * challenge freshness, canonical and unambiguous CSR structure, the attestation statement, equality of the attested
     * and claimed public keys, and all requested attributes. Signature mode additionally verifies the CSR signature and
     * therefore proof of possession. Hash mode reconstructs [AttestationHashInput], hashes its canonical DER encoding,
     * and verifies that digest as the platform attestation nonce; it deliberately performs no private-key operation.
     *
     * [onChallengeValidated] observes a successfully matched challenge. [onPreAttestationError] handles challenge,
     * extraction, transport, structure, binding, key, and requested-attribute failures and may return a client-facing
     * explanation. [onAttestationError] handles failures from platform attestation verification and invalid CSR
     * signatures. Observation-callback exceptions are ignored.
     *
     * [additionalVerifications] runs after generic verification and may return a custom failure. [certificateIssuer] is
     * called only after every check succeeds and receives the verified transport with an [AttestationResult.Verified]
     * receiver.
     */
    suspend fun verifyAttestation(
        attestationProof: AttestationProof,
        onChallengeValidated: suspend AttestationChallenge.(attestationProof: AttestationProof) -> Unit = { },
        onPreAttestationError: suspend PreAttestationError.() -> String? = { null },
        onAttestationError: suspend AttestationResult.Error.(debugInfo: WardenDebugAttestationStatement) -> String? = { null },
        onAttestationSuccess: suspend AttestationResult.Verified.(CryptoPublicKey) -> Unit = { },
        additionalVerifications: suspend AttestationChallenge.(attestationProof: AttestationProof, AttestationResult.Verified) -> AttestationResponse.Failure? = { _, _ -> null },
        certificateIssuer: CertificateIssuerV2,
    ): AttestationResponse {
        val callbacks = VerificationCallbacks(
            onChallengeValidated,
            onPreAttestationError,
            onAttestationError,
            onAttestationSuccess,
            additionalVerifications,
            certificateIssuer,
        )
        return catchingUnwrapped {
            val prepared = when (val result = attestationProof.prepareAttestation(callbacks)) {
                is Preparation.Success -> result.value
                is Preparation.Failure -> return result.response
            }
            val verified = when (val result = prepared.verifyKeyAttestation(callbacks)) {
                is KeyVerification.Success -> result.value
                is KeyVerification.Failure -> return result.response
            }
            with(prepared.challenge) {
                (prepared to verified).verifyProofOfPossession(callbacks)?.let { return it }
                prepared.verifyAttributeAttestations(callbacks)?.let { return it }
                (prepared to verified).finishVerification(callbacks)
            }
        }.getOrElse {
            Failure(
                Type.INTERNAL,
                "Supreme Implementation Error: File a bug: https://github.com/a-sit-plus/warden-supreme/issues/new/choose"
            )
        }

    }

    //Data extraction
    private suspend fun AttestationProof.prepareAttestation(
        callbacks: VerificationCallbacks,
    ): Preparation {
        //get payload; either raw (hashed data auth), or the tbsCsr from a proper CSR (signed data auth)
        val tbsCsr = when (this) {
            is AttestationProof.Hashed -> data
            is AttestationProof.Signed -> data.tbsCsr
        }

        //get challenge from challenge cache (return if it fails)
        val validatedChallenge = when (val result = challengeValidator.validate(this)) {
            is ChallengeValidationResult.Failure.NonceExtraction -> return Preparation.Failure(
                Failure(Type.CONTENT, result.reason.challengeReason(callbacks.onPreAttestationError))
            )

            is ChallengeValidationResult.Failure.Other -> return Preparation.Failure(
                Failure(Type.CONTENT, result.reason(tbsCsr, callbacks.onPreAttestationError))
            )

            is ChallengeValidationResult.Success -> result.validatedChallenge
        }
        val expectedAuthentication = validatedChallenge.dataAuth
        val authenticationMatches = when (this) {
            is AttestationProof.Signed -> expectedAuthentication == DataAuthentication.Signature
            is AttestationProof.Hashed -> expectedAuthentication is DataAuthentication.Hash
        }
        if (!authenticationMatches) {
            return Preparation.Failure(
                clientDataValidationFailure(
                    Type.TRUST,
                    PreAttestationError.ClientDataValidation.Reason.AUTHENTICATION_METHOD_MISMATCH,
                    this,
                    validatedChallenge,
                    callbacks.onPreAttestationError,
                    "Authentication method does not match challenge",
                )
            )
        }
        tbsCsr.csrStructureFailure(this, validatedChallenge, callbacks.onPreAttestationError)
            ?.let { return Preparation.Failure(it) }

        catchingUnwrapped { callbacks.onChallengeValidated(validatedChallenge, this) }

        //raw Signum-Supreme-generated attestation statement from (tbs)CSR attribute
        val statement = tbsCsr.attestationStatementForOid(attestationProofOID).getOrElse {
            return Preparation.Failure(
                Failure(Type.CONTENT, it.extractionReason(this, callbacks.onPreAttestationError))
            )
        }
        val nonceForMakoto = when (this) {
            //easy-peasy
            is AttestationProof.Signed -> validatedChallenge.nonce
            //recompute hash
            is AttestationProof.Hashed -> {
                catchingUnwrapped {
                    val proof = tbsCsr.attributes.single { it.oid == validatedChallenge.proofOID }
                    val hashInput = tbsCsr.toHashInput(validatedChallenge.proofOID)
                    require(
                        hashInput.toTbsCsr(tbsCsr.publicKey, proof).encodeToDer()
                            .contentEquals(tbsCsr.encodeToDer())
                    ) { "TBS CSR does not use the canonical attestation binding" }
                    (expectedAuthentication as DataAuthentication.Hash).algorithm.digest(hashInput.encodeToDer())
                }.getOrElse {
                    return Preparation.Failure(
                        clientDataValidationFailure(
                            Type.CONTENT,
                            PreAttestationError.ClientDataValidation.Reason.ATTESTATION_BINDING,
                            this,
                            validatedChallenge,
                            callbacks.onPreAttestationError,
                            "TBS CSR does not use the canonical attestation binding",
                            it,
                        )
                    )
                }
            }
        }
        //we now we have all inputs for the actual low-level key attestation procedure (nonce, attestation statement)
        //and we also know that the challenge is valid
        return Preparation.Success(
            PreparedAttestation(this, tbsCsr, validatedChallenge, statement, nonceForMakoto)
        )
    }

    private suspend fun TbsCertificationRequest.csrStructureFailure(
        clientData: AttestationProof,
        challenge: AttestationChallenge,
        onPreAttestationError: suspend PreAttestationError.() -> String?,
    ): Failure? {
        if (attributes.map { it.oid }.toSet().size != attributes.size) {
            return clientDataValidationFailure(
                Type.CONTENT,
                PreAttestationError.ClientDataValidation.Reason.DUPLICATE_CSR_ATTRIBUTE_OID,
                clientData,
                challenge,
                onPreAttestationError,
                "CSR attribute OIDs must be distinct",
            )
        }
        attributes.singleOrNull { it.oid == extensionRequestOid }?.let { extensionRequest ->
            val extensions = catchingUnwrapped {
                extensionRequest.value.single().asSequence().map {
                    X509CertificateExtension.decodeFromTlv(it.asSequence())
                }
            }.getOrElse {
                return clientDataValidationFailure(
                    Type.CONTENT,
                    PreAttestationError.ClientDataValidation.Reason.MALFORMED_CSR_EXTENSION_REQUEST,
                    clientData,
                    challenge,
                    onPreAttestationError,
                    "Malformed CSR extension request",
                    it,
                )
            }
            if (extensions.map { it.oid }.toSet().size != extensions.size) {
                return clientDataValidationFailure(
                    Type.CONTENT,
                    PreAttestationError.ClientDataValidation.Reason.DUPLICATE_CSR_EXTENSION_OID,
                    clientData,
                    challenge,
                    onPreAttestationError,
                    "CSR extension OIDs must be distinct",
                )
            }
        }
        return if (attributes.map { it.encodeToTlv() } != Asn1.SetOf { attributes.forEach { +it } }.toList()) {
            clientDataValidationFailure(
                Type.CONTENT,
                PreAttestationError.ClientDataValidation.Reason.NON_CANONICAL_CSR_ATTRIBUTE_ORDER,
                clientData,
                challenge,
                onPreAttestationError,
                "CSR attributes are not in canonical DER order",
            )
        } else null
    }

    private suspend fun PreparedAttestation.verifyKeyAttestation(
        callbacks: VerificationCallbacks,
    ): KeyVerification = with(makoto) {
        //this is just plain key attestation through Makoto
        verifyKeyAttestation(attestationStatement, nonceForMakoto).foldTyped(
            onError = { error ->
                val explanation = error.extractReason(
                    callbacks.onAttestationError,
                    attestationStatement,
                    nonceForMakoto,
                )
                KeyVerification.Failure(
                    when (val cause = error.cause) {
                        is AttestationException.Certificate.Time -> Failure(Type.TIME, explanation)
                        is AttestationException.Content -> when (cause) {
                            is AttestationException.Content.Android -> when (cause.cause.reason) {
                                AttestationValueException.Reason.STATEMENT_TIME -> Failure(Type.TIME, explanation)
                                else -> Failure(Type.CONTENT, explanation)
                            }

                            is AttestationException.Content.iOS -> when (cause.cause.reason) {
                                IosAttestationException.Reason.STATEMENT_TIME -> Failure(Type.TIME, explanation)
                                else -> Failure(Type.CONTENT, explanation)
                            }

                            else -> Failure(Type.CONTENT, explanation)
                        }

                        is AttestationException.Certificate.Trust -> Failure(Type.TRUST, explanation)
                        is AttestationException.Configuration -> Failure(Type.CONTENT, explanation)
                    }
                )
            },
            onSuccess = { publicKey, details ->
                if (publicKey.encoded.contentEquals(tbsCsr.publicKey.encodeToDer())) KeyVerification.Success(
                    VerifiedAttestation(publicKey, details)
                )
                else KeyVerification.Failure(
                    clientDataValidationFailure(
                        Type.TRUST,
                        PreAttestationError.ClientDataValidation.Reason.ATTESTED_PUBLIC_KEY_MISMATCH,
                        attestationProof,
                        challenge,
                        callbacks.onPreAttestationError,
                        "Claimed public key does not match attested public key",
                    )
                )
            },
        )
    }

    //key binding / proof of possession verification
    private suspend fun Pair<PreparedAttestation, VerifiedAttestation>.verifyProofOfPossession(
        callbacks: VerificationCallbacks,
    ): Failure? {
        val (prepared, verified) = this
        val challenge = prepared.challenge
        if (prepared.attestationProof is AttestationProof.Signed) {
            val csr = prepared.attestationProof.data
            val signatureValid = catchingUnwrapped {
                csr.jcaSignature().getOrThrow().run {
                    initVerify(verified.publicKey)
                    update(csr.tbsCsr.encodeToDer())
                    verify(csr.decodedSignature.getOrThrow().jcaSignatureBytes)
                }
            }.getOrElse {
                return Failure(Type.INTERNAL, it.operationalReason(callbacks.onPreAttestationError))
            }
            if (!signatureValid) {
                return Failure(
                    Type.TRUST,
                    csrReason(callbacks.onAttestationError, prepared.attestationStatement, challenge.nonce),
                )
            }
        }

        return null

    }

    //verify that the received (Tbs)CSR contains all required attributes. happens for signature and hash-based data auth
    private suspend fun PreparedAttestation.verifyAttributeAttestations(callbacks: VerificationCallbacks): Failure? {
        val attributes = catchingUnwrapped { with(challenge) { tbsCsr.attestedAttributes() } }.getOrElse {
            return clientDataValidationFailure(
                Type.CONTENT,
                PreAttestationError.ClientDataValidation.Reason.REQUESTED_ATTRIBUTES_EXTRACTION,
                attestationProof,
                challenge,
                callbacks.onPreAttestationError,
                "Requested attributes could not be extracted",
                it,
            )
        }
        catchingUnwrapped { attributes.parsedAttributesBy(challenge) }.exceptionOrNull()?.let {
            return clientDataValidationFailure(
                Type.CONTENT,
                PreAttestationError.ClientDataValidation.Reason.REQUESTED_ATTRIBUTES_MISMATCH,
                attestationProof,
                challenge,
                callbacks.onPreAttestationError,
                "Requested Attributes are not all attested",
                it,
            )
        }
        return null
    }

    private suspend fun Pair<PreparedAttestation, VerifiedAttestation>.finishVerification(
        callbacks: VerificationCallbacks,
    ): AttestationResponse {
        val (prepared, verified) = this
        val challenge = prepared.challenge
        catchingUnwrapped {
            callbacks.additionalVerifications(challenge, prepared.attestationProof, verified.details)
                ?.let { return it }
        }.getOrElse { return Failure(Type.INTERNAL, "Custom checks failed") }

        return catchingUnwrapped {
            callbacks.certificateIssuer(verified.details, prepared.attestationProof)
        }.fold(
            onSuccess = { certificateChain ->
                catchingUnwrapped {
                    callbacks.onAttestationSuccess(
                        verified.details,
                        verified.publicKey.toCryptoPublicKey().getOrThrow()/*TODO mlDSA once Signum supports it*/
                    )
                }
                AttestationResponse.Success(certificateChain)
            },
            onFailure = { Failure(Type.INTERNAL, it.operationalReason(callbacks.onPreAttestationError)) },
        )
    }

    private data class VerificationCallbacks(
        val onChallengeValidated: suspend AttestationChallenge.(AttestationProof) -> Unit,
        val onPreAttestationError: suspend PreAttestationError.() -> String?,
        val onAttestationError: suspend AttestationResult.Error.(WardenDebugAttestationStatement) -> String?,
        val onAttestationSuccess: suspend AttestationResult.Verified.(CryptoPublicKey) -> Unit,
        val additionalVerifications: suspend AttestationChallenge.(AttestationProof, AttestationResult.Verified) -> Failure?,
        val certificateIssuer: CertificateIssuerV2,
    )

    private data class PreparedAttestation(
        val attestationProof: AttestationProof,
        val tbsCsr: TbsCertificationRequest,
        val challenge: AttestationChallenge,
        val attestationStatement: Attestation,
        val nonceForMakoto: ByteArray,
    )

    private data class VerifiedAttestation(
        val publicKey: PublicKey,
        val details: AttestationResult.Verified,
    )

    private sealed interface Preparation {
        data class Success(val value: PreparedAttestation) : Preparation
        data class Failure(val response: AttestationResponse.Failure) : Preparation
    }

    private sealed interface KeyVerification {
        data class Success(val value: VerifiedAttestation) : KeyVerification
        data class Failure(val response: AttestationResponse.Failure) : KeyVerification
    }

    private fun Pkcs10CertificationRequest.jcaSignature(): KmmResult<Signature> =
        (signatureAlgorithm as SpecializedSignatureAlgorithm).getJCASignatureInstance()

    context(challenge: AttestationChallenge)
    private fun TbsCertificationRequest.attestedAttributes() = AttestedAttributes(
        otherAttributesEncoded = challenge.toBeAttestedAttributes?.let { requested ->
            attributes.singleOrNull { it.oid == requested.oid }?.value?.singleOrNull()?.asSequence()
                ?: throw Asn1StructuralException("Requested attested attributes not present")
        },
    )

    private suspend fun csrReason(
        onAttestationError: suspend AttestationResult.Error.(WardenDebugAttestationStatement) -> String?,
        attestationStatement: Attestation,
        nonce: ByteArray,
    ): String? = catchingUnwrapped {
        AttestationResult.Error(
            "CSR signature verification failed",
            AttestationException.Content.Unknown("CSR signature verification failed", IllegalArgumentException())
        ).onAttestationError(makoto.collectDebugInfo(attestationStatement, nonce))
    }.getOrNull()


    private suspend fun Throwable.operationalReason(
        onPreAttestationError: suspend PreAttestationError.() -> String?,
    ): String? = catchingUnwrapped {
        PreAttestationError.OperationalError(this).onPreAttestationError()
    }.getOrNull()

    private suspend fun clientDataValidationFailure(
        type: Type,
        reason: PreAttestationError.ClientDataValidation.Reason,
        clientData: AttestationProof,
        challenge: AttestationChallenge,
        onPreAttestationError: suspend PreAttestationError.() -> String?,
        fallbackExplanation: String,
        throwable: Throwable = IllegalArgumentException(fallbackExplanation),
    ) = Failure(
        type,
        catchingUnwrapped {
            PreAttestationError.ClientDataValidation(reason, clientData, challenge, throwable)
                .onPreAttestationError()
        }.getOrNull() ?: fallbackExplanation,
    )

    private suspend fun AttestationResult.Error.extractReason(
        onAttestationError: suspend AttestationResult.Error.(WardenDebugAttestationStatement) -> String?,
        attestationStatement: Attestation,
        nonce: ByteArray,
    ): String? = catchingUnwrapped {
        onAttestationError(makoto.collectDebugInfo(attestationStatement, nonce))
    }.getOrNull()

    private suspend fun Throwable.challengeReason(
        onPreAttestationError: suspend PreAttestationError.() -> String?,
    ): String? = catchingUnwrapped {
        PreAttestationError.ChallengeExtraction(this).onPreAttestationError()
    }.getOrNull()

    private suspend fun ChallengeValidationResult.Failure.reason(
        tbsCsr: TbsCertificationRequest,
        onPreAttestationError: suspend PreAttestationError.() -> String?,
    ): String? = catchingUnwrapped {
        ChallengeVerification(reason, tbsCsr).onPreAttestationError()
    }.getOrNull()

    private suspend fun Throwable.extractionReason(
        csr: Pkcs10CertificationRequest,
        onPreAttestationError: suspend PreAttestationError.() -> String?,
    ): String? = catchingUnwrapped {
        PreAttestationError.AttestationStatementExtraction(this, csr).onPreAttestationError()
    }.getOrNull()


    private suspend fun Throwable.extractionReason(
        clientData: AttestationProof,
        onPreAttestationError: suspend PreAttestationError.() -> String?,
    ): String? = catchingUnwrapped {
        PreAttestationError.AugmentedAttestationStatementExtraction(this, clientData).onPreAttestationError()
    }.getOrNull()

    companion object {
        /**
         * Configures and initializes an [AttestationVerifier] using the provided configuration, nonce generator, and challenge
         * verifier.
         *
         * Note that the nonce validity will always be the longest validity duration over [SupremeConfiguration.android] and [SupremeConfiguration.ios].
         * If only an Android configuration without a nonce validity duration is provided, this will default to [IosAttestationConfiguration.DEFAULT_VALIDITY_SECONDS].
         *
         * @param configuration The [SupremeConfiguration] object containing Android and/or iOS attestation configurations, attestation proof OID,
         * generic device name OID, default key constraints, and verification time offset.
         * @param nonceGenerator A [NonceGenerator] instance to generate unique challenges for verification. Defaults to [WardenDefaults.nonceGenerator].
         * @param challengeValidator A lambda function that initializes a [ChallengeValidator] based on:
         *  * the provided [SupremeConfiguration.Clock.timeSource]
         *  * the **inverse** [SupremeConfiguration.verificationTimeOffset] because drift in the opposite direction relative to the back end.
         *    Passing the inverse here means straight-forward challenge validation logic without the need to account for who sees what inverted and who doesn't.
         *
         * [configuration].
         * Defaults to using an [InMemoryChallengeCache].
         * @return An instance of [AttestationVerifier] configured with the provided parameters.
         */
        operator fun invoke(
            configuration: SupremeConfiguration,
            nonceGenerator: NonceGenerator = WardenDefaults.nonceGenerator,
            challengeValidator: (Clock, Duration) -> ChallengeValidator = { clock, verificationTimeOffset ->
                InMemoryChallengeCache(clock, verificationTimeOffset)
            }
        ): AttestationVerifier = Makoto(configuration).let { makoto ->
            AttestationVerifier(
                makoto,
                attestationProofOID = configuration.attestationProofOID,
                genericDeviceNameOID = configuration.genericDeviceNameOID,
                defaultKeyConstraints = configuration.defaultKeyConstraints,
                nonceValidity = makoto.longestValidityDuration
                    ?: IosAttestationConfiguration.DEFAULT_VALIDITY_SECONDS.seconds,
                attestableAttributes = configuration.attestableAttributes,
                dataAuth = configuration.dataAuthentication,
                nonceGenerator = nonceGenerator,
                challengeValidator = challengeValidator(
                    configuration.clock.timeSource,
                    -makoto.verificationTimeOffset
                ),
            )
        }
    }
}

/**
 * Invoked from [AttestationVerifier.verifyAttestation]. Useful to match against in-transit attestation processes.
 * Most probably, this will check against a nonce cache and evict any matched nonce from the cache.
 * **Implementing this function in a meaningful manner is absolutely crucial**, since this is the actual challenge
 * matching, ensuring freshness!
 * Challenge nonces are sensitive replay-protection material: implementations and operators should avoid logging them,
 * avoid exposing them across sessions or callers, and rely on protected transport plus caller-aware controls outside the
 * nonce cache when needed.
 *
 * **BEWARE OF CLOCK DRIFT AND CONFIGURED OFFSETS WRT. VALIDITY DURATION!**
 *
 * @see InMemoryChallengeCache for a sane default logic to account for clock drift
 */
interface ChallengeValidator {
    /**
     * The contract of this function is that it stores challenges regardless of their contents and performs no sanity checks.
     * Reason: Strong cryptographic nonces are assumed, making collisions unrealistic
     *
     * Implementations may throw if they cannot store the challenge. For example, [InMemoryChallengeCache] throws
     * [InMemoryChallengeCache.ChallengeCacheFullException] when its bounded in-memory capacity is exhausted.
     */
    @Throws(InMemoryChallengeCache.ChallengeCacheFullException::class)
    suspend fun store(challenge: AttestationChallenge)

    /**
     * The contract of this function is that it returns a [ChallengeValidationResult.Success] iff a valid
     * challenge matching the passed signed CSR or TBS CSR from the client is found.
     * In all other cases, it must return a [ChallengeValidationResult.Failure]:
     * * It must return a [ChallengeValidationResult.Failure.NonceExtraction] if nonce extraction fails (relevant for nonce-cache based implementations)
     * * It must return a [ChallengeValidationResult.Failure.Other] if other validation errors occur, such as no valid challenge matching the request.
     * In addition, it **should** also remove all expired challenges, to keep stale challenges from inflating memory/storage.
     */
    suspend fun validate(csr: Pkcs10CertificationRequest): ChallengeValidationResult
    suspend fun validate(certificationRequestInfo: TbsCertificationRequest): ChallengeValidationResult
}

/** Dispatches challenge validation to the signed-CSR or TBS-CSR overload matching [attestationProof]. */
suspend fun ChallengeValidator.validate(attestationProof: AttestationProof): ChallengeValidationResult =
    when (attestationProof) {
        is AttestationProof.Signed -> this.validate(attestationProof.data)
        is AttestationProof.Hashed -> this.validate(attestationProof.data)
    }

/** Generates a fresh challenge nonce. */
typealias NonceGenerator = suspend () -> ByteArray

/** Result of matching and consuming the challenge referenced by received client data. */
sealed class ChallengeValidationResult {
    /** Contains the exact previously issued challenge matched by the validator. */
    class Success(val validatedChallenge: AttestationChallenge) : ChallengeValidationResult()
    /** Challenge matching failed for [reason]. */
    sealed class Failure(val reason: Throwable) : ChallengeValidationResult() {
        /** The nonce could not be extracted from the received TBS CSR. */
        class NonceExtraction(reason: Throwable) : Failure(reason)
        /** The nonce was extracted, but no acceptable issued challenge was found or consumed. */
        class Other(reason: Throwable) : Failure(reason)
    }
}


/**
 * Compatibility issuer for the signature-only API. Receives the signed CSR after it was thoroughly checked and verified.
 * At this point, the CSR's signature has been verified, the challenge checked, and the public key attested.
 * Hence, a certificate can be issued and the whole certificate chain (from newly issued certificate up to the CA)
 * shall be returned.
 */
typealias CertificateIssuer = suspend AttestationResult.Verified.(Pkcs10CertificationRequest) -> CertificateChain

/**
 * Receives the signed CSR or unsigned TBS CSR from the mobile client after it was thoroughly checked and verified.
 * At this point, the selected authentication mode has been verified, the challenge checked, requested attributes
 * validated, and the public key matched to the attestation statement.
 * Hence, a certificate can be issued and the whole certificate chain (from newly issued certificate up to the CA)
 * shall be returned.
 */
typealias CertificateIssuerV2 = suspend AttestationResult.Verified.(AttestationProof) -> CertificateChain

/** High-level verifier errors exposed to [AttestationVerifier.verifyAttestation]'s `onPreAttestationError` callback. */
sealed class PreAttestationError {
    abstract val throwable: Throwable?

    class ChallengeExtraction(override val throwable: Throwable) : PreAttestationError()
    class ChallengeVerification(
        override val throwable: Throwable?,
        val receivedTbsCsr: TbsCertificationRequest,
    ) : PreAttestationError()

    @Deprecated("Replace with forward-compatible AugmentedAttestationStatementExtraction")
    class AttestationStatementExtraction(override val throwable: Throwable, val csr: Pkcs10CertificationRequest) :
        PreAttestationError()

    class AugmentedAttestationStatementExtraction(
        override val throwable: Throwable,
        val clientData: AttestationProof
    ) :
        PreAttestationError()

    /**
     * Failure while validating the proof transport after its challenge was recovered.
     * [reason] identifies the rejected invariant and [clientData] plus [challenge] provide the complete context.
     */
    class ClientDataValidation(
        val reason: Reason,
        val clientData: AttestationProof,
        val challenge: AttestationChallenge,
        override val throwable: Throwable,
    ) : PreAttestationError() {
        /** Stable categories for client-data validation failures. */
        enum class Reason {
            AUTHENTICATION_METHOD_MISMATCH,
            DUPLICATE_CSR_ATTRIBUTE_OID,
            MALFORMED_CSR_EXTENSION_REQUEST,
            DUPLICATE_CSR_EXTENSION_OID,
            NON_CANONICAL_CSR_ATTRIBUTE_ORDER,
            ATTESTATION_BINDING,
            ATTESTED_PUBLIC_KEY_MISMATCH,
            REQUESTED_ATTRIBUTES_EXTRACTION,
            REQUESTED_ATTRIBUTES_MISMATCH,
        }
    }

    class OperationalError(override val throwable: Throwable) : PreAttestationError()
}


/**
 * Caches issued challenges in memory in a coroutine-safe way. Requires a [clock] and an [offset].
 * The [AttestationVerifier] passes [Makoto]'s clock and the inverse of [Makoto.verificationTimeOffset], since these two values
 * are also encoded into issues challenges.
 *
 * The cache is bounded by [maxChallenges] and throws [InMemoryChallengeCache.ChallengeCacheFullException] from [store]
 * when that many unexpired challenges are already in flight. Expired entries are pruned before the capacity check and a
 * duplicate nonce overwrites the existing entry even at capacity.
 *
 * Production deployments should apply caller-aware rate limiting outside this cache and may prefer a distributed
 * TTL-backed [ChallengeValidator] when multiple verifier instances are used. The cache deliberately owns no backoff
 * state, because backoff needs caller identity, IP, account, or device context.
 *
 * @throws IllegalArgumentException if [maxChallenges] is not positive.
 */
//internal props for testing
class InMemoryChallengeCache
@Throws(IllegalArgumentException::class)
constructor(
    internal val clock: Clock,
    internal val offset: Duration,
    val maxChallenges: Int = DEFAULT_MAX_IN_MEMORY_CHALLENGES,
) : ChallengeValidator {

    companion object {
        const val DEFAULT_MAX_IN_MEMORY_CHALLENGES: Int = 100_000
    }

    class ChallengeCacheFullException(val maxChallenges: Int) :
        IllegalStateException("In-memory challenge cache full: $maxChallenges challenges in flight")

    init {
        require(maxChallenges > 0) { "maxChallenges must be positive" }
    }

    private val mutex = Mutex()

    /**
     * Use a hash map keyed by nonce instead of a list to make lookups O(1) instead of O(n).
     * ByteArray is not suitable as a key directly, so we wrap it.
     */
    private class NonceKey(val bytes: ByteArray) {
        override fun equals(other: Any?): Boolean =
            this === other || (other is NonceKey && bytes.contentEquals(other.bytes))

        override fun hashCode(): Int = bytes.contentHashCode()
        override fun toString(): String = bytes.toHexString()
    }

    private val challengesByNonce = mutableMapOf<NonceKey, AttestationChallenge>()

    @Throws(ChallengeCacheFullException::class)
    override suspend fun store(challenge: AttestationChallenge) {
        mutex.withLock {
            pruneExpiredEntries()
            val key = NonceKey(challenge.nonce)
            // Strong cryptographic nonces make collisions unrealistic, so we simply overwrite
            if (!challengesByNonce.containsKey(key) && challengesByNonce.size >= maxChallenges) {
                throw ChallengeCacheFullException(maxChallenges)
            }
            challengesByNonce[key] = challenge
        }
    }

    override suspend fun validate(csr: Pkcs10CertificationRequest): ChallengeValidationResult = validate(csr.tbsCsr)

    override suspend fun validate(certificationRequestInfo: TbsCertificationRequest): ChallengeValidationResult {
        mutex.withLock {
            val nonce = certificationRequestInfo.nonce.getOrElse {
                return ChallengeValidationResult.Failure.NonceExtraction(it)
            }
            pruneExpiredEntries()
            return find(nonce)
        }
    }

    private fun find(nonce: ByteArray): ChallengeValidationResult {
        val key = NonceKey(nonce)
        val challenge = challengesByNonce.remove(key) ?: return ChallengeValidationResult.Failure.Other(
            IllegalStateException("No challenge found")
        )

        // With a Map, you can't have multiple active entries for the same nonce
        // unless you deliberately store a collection. Given strong random nonces,
        // we assume at most one.
        return ChallengeValidationResult.Success(challenge)
    }

    private fun pruneExpiredEntries() {
        // Capture time once per call instead of per-entry
        val nowWithOffset = clock.now() + offset

        val iterator = challengesByNonce.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (entry.value.validUntil <= nowWithOffset) {
                iterator.remove()
            }
        }
    }
}
