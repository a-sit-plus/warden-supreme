package at.asitplus.attestation

import at.asitplus.attestation.android.*
import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.attestation.android.exceptions.CertificateInvalidException
import at.asitplus.attestation.android.exceptions.RevocationException
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.AndroidKeystoreAttestation
import at.asitplus.signum.indispensable.Attestation
import at.asitplus.signum.indispensable.IosHomebrewAttestation
import at.asitplus.signum.indispensable.toJcaPublicKey
import ch.veehait.devicecheck.appattest.AppleAppAttest
import ch.veehait.devicecheck.appattest.assertion.Assertion
import ch.veehait.devicecheck.appattest.assertion.AssertionChallengeValidator
import ch.veehait.devicecheck.appattest.attestation.AttestationValidator
import ch.veehait.devicecheck.appattest.attestation.ValidatedAttestation
import ch.veehait.devicecheck.appattest.common.App
import ch.veehait.devicecheck.appattest.common.AppleAppAttestEnvironment
import ch.veehait.devicecheck.appattest.receipt.ReceiptException
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import net.swiftzer.semver.SemVer
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.DLTaggedObject
import org.bouncycastle.cert.X509CertificateHolder
import org.slf4j.LoggerFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.cert.CertPathValidatorException
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import kotlin.math.max
import kotlin.math.min
import kotlin.time.*
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/**
 * Default, functional Android and Apple App and Key Attestation in all its glory.
 *
 * Once configured, this class provides a streamlined interface for mobile client attestation
 *
 * @param androidAttestationConfiguration Configuration for Android key attestation.
 * See [AndroidAttestationConfiguration]
 * for details.
 * @param iosAttestationConfiguration IOS AppAttest configuration.  See [IosAttestationConfiguration] for details.
 * @param clock a clock to set the time of verification (used for certificate validity checks)
 * @param verificationTimeOffset allows for fine-grained clock drift compensation (this offsets the certificate validity duration checks and attestation statement validity checks); can be negative. **Note that this is a real offset, shifting the time window of validity, not extending it!**
 *
 * @throws IllegalArgumentException if neither Android nor iOS attestation configuration is provided
 */
@OptIn(ExperimentalTime::class)
class Makoto
@Throws(IllegalArgumentException::class) private constructor(
    val iosAttestationConfiguration: IosAttestationConfiguration?,
    val androidAttestationConfiguration: AndroidAttestationConfiguration?,
    val clock: Clock = Clock.System,
    val verificationTimeOffset: Duration = DEFAULT_TIME_OFFSET
) : AttestationService() {

    init {
        require(androidAttestationConfiguration != null || iosAttestationConfiguration != null) { "At least one attestation configuration (iOS or Android) must be provided" }
    }

    /**
     * Default, functional Android and Apple App and Key Attestation in all its glory.
     *
     * Once configured, this class provides a streamlined interface for mobile client attestation
     *
     * @param androidAttestationConfiguration Configuration for Android key attestation.
     * See [AndroidAttestationConfiguration]
     * for details.
     * @param iosAttestationConfiguration IOS AppAttest configuration.  See [IosAttestationConfiguration] for details.
     * @param clock a clock to set the time of verification (used for certificate validity checks)
     * @param verificationTimeOffset allows for fine-grained clock drift compensation (this offsets the certificate validity duration checks and attestation statement validity checks); can be negative. **Note that this is a real offset, shifting the time window of validity, not extending it!**
     *
     * @throws IllegalArgumentException if neither Android nor iOS attestation configuration is provided
     */
    constructor(
        androidAttestationConfiguration: AndroidAttestationConfiguration,
        iosAttestationConfiguration: IosAttestationConfiguration,
        clock: Clock = Clock.System,
        verificationTimeOffset: Duration = DEFAULT_TIME_OFFSET
    ) : this(iosAttestationConfiguration, androidAttestationConfiguration, clock, verificationTimeOffset)

    /**
     * Android-only App and Key Attestation
     *
     * Once configured, this class provides a streamlined interface for mobile client attestation
     *
     * @param androidAttestationConfiguration Configuration for Android key attestation.
     * See [AndroidAttestationConfiguration]
     * for details.
     * @param clock a clock to set the time of verification (used for certificate validity checks)
     * @param verificationTimeOffset allows for fine-grained clock drift compensation (this offsets the certificate validity duration checks and attestation statement validity checks); can be negative. **Note that this is a real offset, shifting the time window of validity, not extending it!**
     *
     * @throws IllegalArgumentException if neither Android nor iOS attestation configuration is provided
     */
    constructor(
        androidAttestationConfiguration: AndroidAttestationConfiguration,
        clock: Clock = Clock.System,
        verificationTimeOffset: Duration = DEFAULT_TIME_OFFSET
    ) : this(iosAttestationConfiguration = null, androidAttestationConfiguration, clock, verificationTimeOffset)


    /**
     * iOS-only and Apple App and Key Attestation.
     *
     * Once configured, this class provides a streamlined interface for mobile client attestation
     *
     * @param iosAttestationConfiguration IOS AppAttest configuration.  See [IosAttestationConfiguration] for details.
     * @param clock a clock to set the time of verification (used for certificate validity checks)
     * @param verificationTimeOffset allows for fine-grained clock drift compensation (this offsets the certificate validity duration checks and attestation statement validity checks); can be negative. **Note that this is a real offset, shifting the time window of validity, not extending it!**
     *
     * @throws IllegalArgumentException if neither Android nor iOS attestation configuration is provided
     */
    constructor(
        iosAttestationConfiguration: IosAttestationConfiguration,
        clock: Clock = Clock.System,
        verificationTimeOffset: Duration = DEFAULT_TIME_OFFSET
    ) : this(iosAttestationConfiguration, androidAttestationConfiguration = null, clock, verificationTimeOffset)

    /**
     * Java-friendly constructor with `java.time` types
     *
     * @param androidAttestationConfigurationJ Configuration for Android key attestation. See [AndroidAttestationConfiguration]
     * @param iosAttestationConfigurationJ IOS AppAttest configuration.  See [IosAttestationConfiguration] for details.
     * @param verificationTimeOffsetJ allows for fine-grained clock drift compensation (this duration is added to the certificate
     * validity checks); can be negative. Note that [androidAttestationConfiguration] is the exact same [configuration format as used by
     * Roboto](https://a-sit-plus.github.io/warden-supreme/dokka/roboto/at.asitplus.attestation.android/-android-attestation-configuration/index.html),
     * which also supports setting a verification time offset.
     * For the sake of consistency and intelligibility, **only** set this offset globally and not inside [androidAttestationConfigurationJ].
     * @param javaClock a clock to set the time of verification (used for certificate validity checks)
     *
     * @throws IllegalArgumentException if neither Android nor iOS attestation configuration is provided
     */
    @Throws(IllegalArgumentException::class)
    @JvmOverloads
    constructor(
        iosAttestationConfigurationJ: IosAttestationConfiguration,
        androidAttestationConfigurationJ: AndroidAttestationConfiguration,
        verificationTimeOffsetJ: java.time.Duration = DEFAULT_TIME_OFFSET.toJavaDuration(),
        javaClock: java.time.Clock = java.time.Clock.systemUTC()
    ) : this(
        iosAttestationConfigurationJ,
        androidAttestationConfigurationJ,
        javaClock.toKotlinClock(),
        verificationTimeOffsetJ.toKotlinDuration()
    )

    /**
     * Android-only Java-friendly constructor with `java.time` types
     *
     * @param androidAttestationConfigurationJ Configuration for Android key attestation. See [AndroidAttestationConfiguration]
     * @param verificationTimeOffsetJ allows for fine-grained clock drift compensation (this duration is added to the certificate
     * validity checks); can be negative. Note that [androidAttestationConfiguration] is the exact same [configuration format as used by
     * Roboto](https://a-sit-plus.github.io/warden-supreme/dokka/roboto/at.asitplus.attestation.android/-android-attestation-configuration/index.html),
     * which also supports setting a verification time offset.
     * For the sake of consistency and intelligibility, **only** set this offset globally.
     * @param javaClock a clock to set the time of verification (used for certificate validity checks)
     *
     * @throws IllegalArgumentException if neither Android nor iOS attestation configuration is provided
     */
    @Throws(IllegalArgumentException::class)
    @JvmOverloads
    constructor(
        androidAttestationConfigurationJ: AndroidAttestationConfiguration,
        verificationTimeOffsetJ: java.time.Duration = DEFAULT_TIME_OFFSET.toJavaDuration(),
        javaClock: java.time.Clock = java.time.Clock.systemUTC()
    ) : this(
        iosAttestationConfiguration = null,
        androidAttestationConfigurationJ,
        javaClock.toKotlinClock(),
        verificationTimeOffsetJ.toKotlinDuration()
    )

    /**
     * iOS-only Java-friendly constructor with `java.time` types
     *
     * @param iosAttestationConfigurationJ IOS AppAttest configuration.  See [IosAttestationConfiguration] for details.
     * @param verificationTimeOffsetJ allows for fine-grained clock drift compensation (this duration is added to the certificate
     * validity checks); can be negative.
     * @param javaClock a clock to set the time of verification (used for certificate validity checks)
     *
     * @throws IllegalArgumentException if neither Android nor iOS attestation configuration is provided
     */
    @Throws(IllegalArgumentException::class)
    @JvmOverloads
    constructor(
        iosAttestationConfigurationJ: IosAttestationConfiguration,
        verificationTimeOffsetJ: java.time.Duration = DEFAULT_TIME_OFFSET.toJavaDuration(),
        javaClock: java.time.Clock = java.time.Clock.systemUTC()
    ) : this(
        iosAttestationConfigurationJ,
        androidAttestationConfiguration = null,
        javaClock.toKotlinClock(),
        verificationTimeOffsetJ.toKotlinDuration()
    )

    private val log = LoggerFactory.getLogger(this.javaClass)


    private val androidAttestationVerifier: Roboto? = androidAttestationConfiguration?.let { cfg ->
        val androidOffset = catchingUnwrapped {
            Math.addExact(
                verificationTimeOffset.inWholeSeconds,
                cfg.verificationSecondsOffset
            )
        }.getOrElse {
            throw AttestationException.Configuration(
                Platform.ANDROID,
                "Offset too large!",
                cause = it
            )
        }

        val correctlyOffsetAndroidConfig =
            androidAttestationConfiguration.copy(verificationSecondsOffset = androidOffset)

        catchingUnwrapped {  Roboto(correctlyOffsetAndroidConfig){ expected, actual -> expected contentEquals actual }}.getOrElse {
            throw  throw AttestationException.Configuration(
                Platform.ANDROID,
                it.message,
                cause = it
            )
        }

    }

    private val iosSetup = catchingUnwrapped {
        iosAttestationConfiguration?.let {
            IosSetup(
                it,
                clock,
                verificationTimeOffset
            )
        }
    }.getOrElse {
        throw AttestationException.Configuration(
            Platform.IOS, it.message, it
        )
    }

    /**
     * The shortest attestation validity duration over Android and iOS configuration.
     * Useful to get the shortest sensible nonce validity duration
     */
    val shortestValidityDuration: Duration? = shortestDurationInternal(
        iosAttestationConfiguration?.attestationStatementValiditySeconds,
        androidAttestationConfiguration?.attestationStatementValiditySeconds
    )


    /**
     * The longest attestation validity duration over Android and iOS configuration.
     * Useful to get the longest sensible nonce validity duration
     */
    val longestValidityDuration: Duration? = longestDurationInternal(
        iosAttestationConfiguration?.attestationStatementValiditySeconds,
        androidAttestationConfiguration?.attestationStatementValiditySeconds
    )

    override val ios = object : IOS {
        override fun verifyAppAttestation(attestationObject: ByteArray, challenge: ByteArray) =
            verifyAttestationApple(attestationObject, challenge, assertionData = null, counter = 0L)

        override fun verifyAssertion(
            attestationObject: ByteArray,
            assertionFromDevice: ByteArray,
            referenceClientData: ByteArray,
            challenge: ByteArray,
            counter: Long
        ) = verifyAttestationApple(
            attestationObject,
            challenge,
            assertionData = AssertionData(assertionFromDevice, referenceClientData),
            counter
        )
    }

    override val android = object : Android {
        override suspend fun verifyKeyAttestation(
            attestationCerts: List<X509Certificate>,
            expectedChallenge: ByteArray
        ) = verifyKeyAttestation<PublicKey>(
            attestationCerts.map { it.encoded },
            expectedChallenge,
            attestationCerts.first().publicKey
        )
    }

    /**
     * Collects a debug dump of an attestation call.
     * Use this if you called ```verifyAttestation(
     *               attestationProof: List<ByteArray>,
     *               challenge: ByteArray,
     *               clientData: ByteArray?
     *           ): AttestationResult```
     *
     *  The resulting [WardenDebugAttestationStatement] features JSON-based`.serialize()` and `deserialize()` methods
     */
    @JvmName("collectKeyAttestationLegacy")
    fun collectDebugInfo(
        attestationProof: List<ByteArray>,
        challenge: ByteArray,
        clientData: ByteArray? = null
    ) = WardenDebugAttestationStatement(
        method = WardenDebugAttestationStatement.Method.LEGACY,
        androidAttestationConfiguration = androidAttestationConfiguration,
        iosAttestationConfiguration = iosAttestationConfiguration,
        genericAttestationProof = attestationProof,
        challenge = challenge,
        clientData = clientData,
        verificationTime = clock.now(),
        verificationTimeOffset = verificationTimeOffset,
        version = version
    )


    /**
     * Collects a debug dump of an attestation call.
     * Use this if you called ``` <T : PublicKey> verifyKeyAttestation(
     *         attestationProof: List<ByteArray>,
     *         expectedChallenge: ByteArray,
     *         keyToBeAttested: T
     *     )```
     *
     *  The resulting [WardenDebugAttestationStatement] features JSON-based`.serialize()` and `deserialize()` methods
     */
    fun collectDebugInfo(
        attestationProof: List<ByteArray>,
        challenge: ByteArray,
        publicKey: PublicKey
    ) = WardenDebugAttestationStatement(
        method = WardenDebugAttestationStatement.Method.KEY_ATTESTATION_LEGACY,
        androidAttestationConfiguration = androidAttestationConfiguration,
        iosAttestationConfiguration = iosAttestationConfiguration,
        genericAttestationProof = attestationProof,
        challenge = challenge,
        clientData = publicKey.encoded,
        verificationTime = clock.now(),
        verificationTimeOffset = verificationTimeOffset,
        version = version
    )

    /**
     * Collects a debug dump of an attestation call.
     * Use this if you called  ```verifyKeyAttestation(
     *         attestationProof: List<ByteArray>,
     *         challenge: ByteArray,
     *         encodedPublicKey: ByteArray
     *     ): KeyAttestation<PublicKey>```
     *
     *  The resulting [WardenDebugAttestationStatement] features JSON-based`.serialize()` and `deserialize()` methods
     */
    fun collectDebugInfo(
        attestationProof: List<ByteArray>,
        challenge: ByteArray,
        rawPublicKey: ByteArray
    ) = WardenDebugAttestationStatement(
        method = WardenDebugAttestationStatement.Method.KEY_ATTESTATION_LEGACY_RAW,
        androidAttestationConfiguration = androidAttestationConfiguration,
        iosAttestationConfiguration = iosAttestationConfiguration,
        genericAttestationProof = attestationProof,
        challenge = challenge,
        clientData = rawPublicKey,
        verificationTime = clock.now(),
        verificationTimeOffset = verificationTimeOffset,
        version = version
    )

    /**
     * Collects a debug dump of an attestation call.
     * Use this if you called ```verifyKeyAttestation(
     *         attestationProof: Attestation,
     *         challenge: ByteArray
     *     ): KeyAttestation<PublicKey>```
     *
     *  The resulting [WardenDebugAttestationStatement] features JSON-based`.serialize()` and `deserialize()` methods
     */
    fun collectDebugInfo(
        attestationProof: Attestation,
        challenge: ByteArray
    ) = WardenDebugAttestationStatement(
        method = WardenDebugAttestationStatement.Method.SUPREME,
        androidAttestationConfiguration = androidAttestationConfiguration,
        iosAttestationConfiguration = iosAttestationConfiguration,
        keyAttestation = attestationProof,
        challenge = challenge,
        verificationTime = clock.now(),
        verificationTimeOffset = verificationTimeOffset,
        version = version
    )

    override suspend fun verifyAttestation(
        attestationProof: List<ByteArray>,
        challenge: ByteArray,
        clientData: ByteArray?
    ): AttestationResult {
        log.debug("attestation proof length: ${attestationProof.size}")
        return if (attestationProof.isEmpty())
            IllegalArgumentException().encapsulateToUnknown("Attestation proof is empty")
        else if (attestationProof.size > 2) verifyAttestationAndroid(attestationProof, challenge).let {
            if (it is AttestationResult.Android) clientData?.let { encodedKey ->
                if (!it.attestationCertificate.publicKey.encoded.contentEquals(encodedKey)) {
                    "Attestation certificate public key does not match provided public key".let { msg ->
                        AttestationResult.Error(
                            msg, AttestationException.Content.Android(
                                msg,
                                AttestationValueException(
                                    msg, reason = AttestationValueException.Reason.APP_UNEXPECTED,
                                    expectedValue = encodedKey,
                                    actualValue = it.attestationCertificate.publicKey.encoded
                                )
                            )
                        )
                    }
                } else it
            } ?: it
            else it
        }
        else {
            catchingUnwrapped {
                verifyAttestationApple(
                    attestationProof.first(),
                    challenge,
                    clientData?.let { AssertionData(attestationProof[1], it) },
                    counter = 0L
                )

            }.getOrElse {
                //if attestationProof contains no assertion, but clientData is set, for example
                log.warn("Could not verify attestation proof: {}", attestationProof.map { it.encodeBase64() })
                return if (it is IndexOutOfBoundsException)
                    it.encapsulateToUnknown("Invalid length of attestation proof: ${it.message}")
                else it.encapsulateToUnknown(
                    "Could not verify client integrity due to internal error: " +
                            "${it::class.simpleName}${it.message?.let { ". $it" }}"
                )
            }
        }
    }

    override suspend fun doVerifyKeyAttestation(
        attestationProof: Attestation,
        challenge: ByteArray
    ): KeyAttestation<PublicKey> =
        when (attestationProof) {
            is IosHomebrewAttestation -> {
                if (IosHomebrewAttestation.ClientData(
                        attestationProof.parsedClientData.publicKey,
                        challenge
                    ) != attestationProof.parsedClientData
                )
                    KeyAttestation(
                        null, AttestationResult.Error(
                            "Challenge mismatch",
                            AttestationException.Content.iOS(cause = IosAttestationException(reason = IosAttestationException.Reason.CHALLENGE))
                        )
                    )
                else
                    verifyAttestationApple(
                        attestationProof.attestation,
                        attestationProof.clientDataJSON,
                        assertionData = null,
                        counter = 0L
                    ).let {
                        when (it) {
                            is AttestationResult.IOS -> KeyAttestation(
                                attestationProof.parsedClientData.publicKey.toJcaPublicKey().getOrThrow(), it
                            )

                            is AttestationResult.Error -> KeyAttestation(null, it)
                            is AttestationResult.Android -> KeyAttestation(
                                null,
                                AttestationResult.Error(
                                    "Implementation Error. File a bug: https://github.com/a-sit-plus/warden-supreme/issues/new/choose",
                                    AttestationException.Content.Unknown(
                                        "Implementation Error. File a bug: https://github.com/a-sit-plus/warden-supreme/issues/new/choose",
                                        IllegalArgumentException()
                                    )
                                )
                            )
                        }
                    }
            }

            is AndroidKeystoreAttestation -> verifyAttestationAndroid(
                attestationProof.certificateChain.map { it.encodeToDer() },
                challenge
            ).let {
                when (it) {
                    is AttestationResult.Android -> KeyAttestation(
                        attestationProof.certificateChain.first().decodedPublicKey.getOrThrow().toJcaPublicKey()
                            .getOrThrow(), it
                    )

                    is AttestationResult.Error -> KeyAttestation(null, it)
                    is AttestationResult.IOS -> KeyAttestation(
                        null,
                        AttestationResult.Error(
                            "Implementation Error. File a bug: https://github.com/a-sit-plus/warden-supreme/issues/new/choose",
                            AttestationException.Content.Unknown(
                                "Implementation Error. File a bug: https://github.com/a-sit-plus/warden-supreme/issues/new/choose",
                                IllegalArgumentException()
                            )
                        )
                    )
                }
            }

            //Signum will remove IosLegacyHomebrewAttestation in new version
            else -> KeyAttestation(
                null,
                AttestationResult.Error(
                    "${attestationProof::class.simpleName} is unsupported",
                    AttestationException.Content.Unknown(
                        "${attestationProof::class.simpleName} is unsupported",
                        cause = IllegalArgumentException()
                    )
                )
            )

        }

    /**
     * Verifies [Android Key Attestation](https://developer.android.com/training/articles/security-key-attestation) based
     * the provided certificate chain (the leaf ist the attestation certificate, the root must be one of the
     * [Google Hardware Attestation Root certificates](https://developer.android.com/training/articles/security-key-attestation#root_certificate)).
     *
     * @param attestationCerts certificate chain from the attestation certificate up to a Google Hardware Attestation Root certificate
     * @param expectedChallenge the challenge to be verified against
     *
     * @return [AttestationResult.Android] on success [AttestationResult.Error] in case attestation failed
     */
    private suspend fun verifyAttestationAndroid(
        attestationCerts: List<ByteArray>,
        expectedChallenge: ByteArray
    ): AttestationResult = catchingUnwrapped {
        if (androidAttestationVerifier == null) throw AttestationException.Configuration(
            Platform.ANDROID,
            message = "Android Attestation is not configured",
            IllegalArgumentException()
        )
        log.debug("Verifying Android attestation")
        if (attestationCerts.isEmpty()) return AttestationResult.Error(
            "Android attestation proof is empty",
            AttestationException.Content.Unknown(
                "Android attestation proof is empty",
                IllegalArgumentException()
            )
        )
        val certificates = attestationCerts.mapNotNull { it.parseToCertificate() }
        if (certificates.size != attestationCerts.size)
            return AttestationResult.Error(
                "Could not parse Android attestation certificate chain",
                AttestationException.Content.Android(
                    "Could not parse Android attestation certificate chain",
                    cause = AttestationValueException(
                        "At least one certificate failed to parse",
                        reason = AttestationValueException.Reason.APP_UNEXPECTED,
                        expectedValue = attestationCerts.size,
                        actualValue = certificates.size
                    )
                )
            )

        //throws exception on fail, so if we get past it -> all green
        androidAttestationVerifier.verifyAttestation(certificates, (clock.now()).toJavaDate(),expectedChallenge)

        AttestationResult.Android.Verified(certificates)
    }.getOrElse {
        AttestationResult.Error(
            "Android Attestation Error: " + (it.message ?: it::class.simpleName),
            it as? AttestationException.Configuration
                ?: if ((it is CertificateInvalidException) && (it.reason == CertificateInvalidException.Reason.TIME)) AttestationException.Certificate.Time.Android(
                    cause = it
                )
                else if (it is RevocationException) AttestationException.Certificate.Trust.Android(it.message, it)
                else if (it is CertificateInvalidException) AttestationException.Certificate.Trust.Android(cause = it)
                else if (it is CertificateException) AttestationException.Certificate.Trust.Android(
                    cause = CertificateInvalidException(
                        message = it.message ?: "",
                        cause = it,
                        reason = CertificateInvalidException.Reason.TRUST,
                        certificateChain = attestationCerts.mapNotNull { it.parseToCertificate() },
                        invalidCertificate = null
                    )
                ) else if (it is AttestationValueException) AttestationException.Content.Android(
                    cause = it,
                    message = it.message
                )
                else AttestationException.Content.Android(
                    cause = AttestationValueException(
                        message = it.message,
                        cause = it,
                        reason = AttestationValueException.Reason.APP_UNEXPECTED,
                        expectedValue = "",
                        actualValue = null
                    )
                )
        )
    }

    /**
     * Verifies an Apple [AppAttest attestation statement](https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server#3576643)
     * It is optionally possible to pass an [assertionData] pair, mapping an
     * [assertion](https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server#3576644)
     * to a `clientData` [ByteArray].
     * The signature counter in the attestation must be `0` and the signature counter in the assertion must be `1`,
     * meaning that a fresh attestation statement must have been created. If [assertionData] is present, this freshly
     * attested key must have been used exactly once to sign the `clientData` object contained within [assertionData]
     *
     * Passing a public key created in the same app on the iDevice's secure hardware as `clientData` effectively
     * emulates Android's key attestation: Attesting such a secondary key through an assertion, proves that
     * it was also created within the same app, on the same device, resulting in an attested key, which can then be used
     * for general-purpose crypto. **BEWARE if you pass the public key on iOS to be signed as is. iOS uses the ANSI X9.63
     * format represent public keys, so conversion is needed**
     *
     * @param attestationObject the AppAttest Attestation object. Must be freshly created (i.e. signature counter must be zero)
     * @param expectedChallenge the challenge to be verified against
     * @param assertionData optional assertion data containing `clientData` and an [assertion](https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server#3576644)
     * @param counter highest expected value of the signature counter before the assertion was created (if present). Defaults to 0
     *
     * @return [AttestationResult.IOS.Verified] on success when using the [Makoto] ([AttestationResult.IOS]
     * when using [NoopAttestationService]) and [AttestationResult.Error] when attestation fails.
     *
     */
    private fun verifyAttestationApple(
        attestationObject: ByteArray,
        expectedChallenge: ByteArray,
        assertionData: AssertionData?,
        counter: Long
    ): AttestationResult = catchingUnwrapped {
        if (iosSetup == null) throw AttestationException.Configuration(
            Platform.IOS,
            message = "iOS Attestation is not configured",
            IllegalArgumentException()
        )
        log.debug("Verifying iOS attestation")

        val parsedAttestationCert =
            X509CertificateHolder(appAttestReader.readValue<AttestationObject>(attestationObject).attStmt.x5c.first())

        val results = iosSetup.attestationValidators.map { (app, validators) ->

            //this exception is a also encompasses trust anchor mismatches
            var res: Result<ValidatedAttestation> = Result.failure(ReceiptException.InvalidCertificateChain(""))
            validators.forEach { attestationValidator ->
                //check for trust-anchor mismatch
                if (res.isFailure && (res.exceptionOrNull() is ReceiptException.InvalidCertificateChain)) {
                    res = catchingUnwrapped {
                        attestationValidator.validate(
                            attestationObject = attestationObject,
                            keyIdBase64 = MessageDigest.getInstance("SHA-256")
                                .digest(parsedAttestationCert.subjectPublicKeyInfo.publicKeyData.bytes)
                                .encodeBase64(),
                            serverChallenge = expectedChallenge,
                        )
                    }
                }
                //else we NOOP through the rest of the configured validators (and thus through configured trust anchors)
                //if a trust anchor mismatched, the above if clause is tried with the next validator in line
            }
            //and app to result, so we get the one successful result (if any)
            app to res
        }

        if (results.filter { (_, result) -> result.isFailure }.size == results.size)
            throw results.first().second.exceptionOrNull()!!

        val result: Pair<AppleAppAttest, ValidatedAttestation> =
            results.first { (_, result) -> result.isSuccess }.let { (app, res) -> app to res.getOrNull()!! }


        val notBefore =
            result.second.receipt.payload.notBefore?.value ?: result.second.receipt.payload.creationTime.value
        if (notBefore > iosSetup.appAttestClock.instant())
            throw AttestationException.Content.iOS(
                message = "Attestation statement created after ${iosSetup.appAttestClock.instant()}: $notBefore",
                cause = IosAttestationException(reason = IosAttestationException.Reason.STATEMENT_TIME)
            )

        val iosVersion =
            iosSetup.iosApps.entries.firstOrNull { (_, appAttest) -> appAttest.app == result.first.app }?.key?.iosVersionOverride
                ?: iosSetup.iosVersion

        var parsedVersion: ParsedVersions = null to null
        iosVersion?.let { configuredVersion ->
            parsedVersion = parseIosBuildOrVersionNumber(result.second.certificate)
            catchingUnwrapped {
                if (configuredVersion > parsedVersion) {
                    val explanation =
                        "Parsed iOS versions (${parsedVersion.first}, ${parsedVersion.second}) < $configuredVersion"

                    return AttestationResult.Error(
                        explanation,
                        AttestationException.Content.iOS(
                            explanation,
                            cause = IosAttestationException(
                                explanation,
                                reason = IosAttestationException.Reason.OS_VERSION
                            )
                        )
                    )
                }
            }.getOrElse {
                (it.message ?: "Error comparing iOS Versions").let { msg ->
                    return AttestationResult.Error(
                        msg,
                        AttestationException.Content.iOS(
                            msg,
                            cause = IosAttestationException(
                                msg,
                                cause = it,
                                reason = IosAttestationException.Reason.OS_VERSION
                            )
                        )
                    )
                }
            }
        }

        return assertionData?.let { assertionData ->
            runCatching {
                val assertion = result.first.createAssertionValidator(object : AssertionChallengeValidator {
                    override fun validate(
                        assertionObj: Assertion,
                        clientData: ByteArray,
                        attestationPublicKey: ECPublicKey,
                        challenge: ByteArray,
                    ) = challenge contentEquals expectedChallenge
                }).validate(
                    assertionData.assertion,
                    assertionData.clientData,
                    result.second.certificate.publicKey as ECPublicKey,
                    counter,
                    expectedChallenge
                )
                return if (assertion.authenticatorData.signCount != 1L) "iOS Assertion counter is ${assertion.authenticatorData.signCount}, but should be 1".let { msg ->
                    AttestationResult.Error(
                        msg,
                        AttestationException.Content.iOS(
                            msg,
                            cause = IosAttestationException(msg, reason = IosAttestationException.Reason.SIG_CTR)
                        )
                    )
                }
                else AttestationResult.IOS.Verified(result.second, parsedVersion, assertionData.clientData to assertion)
            }.getOrElse {
                AttestationResult.Error(
                    it.message ?: "iOS Assertion validation error due to ${it::class.simpleName}",
                    encapsulateIosAttestationException(it)

                )
            }
        } ?: AttestationResult.IOS.Verified(result.second, parsedVersion, null)

    }.getOrElse {
        AttestationResult.Error(
            it.message ?: "iOS Attestation failed due to ${it::class.simpleName}",
            encapsulateIosAttestationException(it)
        )
    }

    //the following three functions are ripped and adapted from https://github.com/veehaitch/devicecheck-appattest
    private inline fun <reified T : Any> ASN1InputStream.readObjectAs(): T = this.readObject() as T
    private fun getTaggedOctetString(credCert: X509Certificate, oid: String, tagNo: Int): DEROctetString? {
        val value = credCert.getExtensionValue(oid)
        val envelope = ASN1InputStream(value).readObjectAs<DEROctetString>()
        val sequence = ASN1InputStream(envelope.octetStream).readObjectAs<DLSequence>()
        val taggedObject =
            sequence.firstOrNull {
                (it is DLTaggedObject) && it.tagNo == tagNo
                        && (it.baseObject as DEROctetString).octets.isNotEmpty()
            } as DLTaggedObject?
        return taggedObject?.baseObject as DEROctetString?
    }

    private fun parseIosBuildOrVersionNumber(credCert: X509Certificate): ParsedVersions = runCatching {
        getTaggedOctetString(
            credCert = credCert,
            oid = AttestationValidator.AppleCertificateExtensions.OS_VERSION_OID,
            tagNo = AttestationValidator.AppleCertificateExtensions.OS_VERSION_TAG_NO,
        )?.octets?.let(::String)?.let { SemVer.parse(it) }
    }.getOrNull() to getTaggedOctetString(
        credCert = credCert,
        oid = AttestationValidator.AppleCertificateExtensions.OS_VERSION_OID,
        //the SemVer-encoded iOS version and the build number use distinct tags, which are three numbers apart
        tagNo = AttestationValidator.AppleCertificateExtensions.OS_VERSION_TAG_NO + 3,
    )?.octets?.let(::String)?.let { it.toBuildNumber() }

    private fun encapsulateIosAttestationException(it: Throwable): AttestationException {
        /*@formatter:off*/
        return it as? AttestationException.Configuration ?: if (it is ch.veehait.devicecheck.appattest.attestation.AttestationException) {
            /*@formatter:on*/
            when (it) {
                is ch.veehait.devicecheck.appattest.attestation.AttestationException.InvalidAuthenticatorData -> {
                    AttestationException.Content.iOS(
                        cause = IosAttestationException(
                            cause = it,
                            reason = if (it.message?.startsWith("App ID does not match RP ID hash") == true ||
                                it.message?.startsWith("AAGUID does match neither") == true
                            ) IosAttestationException.Reason.IDENTIFIER else IosAttestationException.Reason.APP_UNEXPECTED
                        )
                    )
                }

                is ch.veehait.devicecheck.appattest.attestation.AttestationException.InvalidCertificateChain -> {
                    var ex = it.cause
                    while (ex !is CertPathValidatorException) {
                        if (ex == null) return AttestationException.Certificate.Trust.iOS(cause = it)
                        ex = ex.cause
                    }
                    if ((ex.reason == CertPathValidatorException.BasicReason.NOT_YET_VALID) || (ex.reason == CertPathValidatorException.BasicReason.EXPIRED))
                        AttestationException.Certificate.Time.iOS(cause = ex)
                    else AttestationException.Certificate.Trust.iOS(cause = ex)
                }

                is ch.veehait.devicecheck.appattest.attestation.AttestationException.InvalidFormatException,
                is ch.veehait.devicecheck.appattest.attestation.AttestationException.InvalidPublicKey ->
                    AttestationException.Content.iOS(
                        cause = IosAttestationException(
                            cause = it,
                            reason = IosAttestationException.Reason.APP_UNEXPECTED
                        )
                    )

                is ch.veehait.devicecheck.appattest.attestation.AttestationException.InvalidNonce ->
                    AttestationException.Content.iOS(
                        it.message,
                        IosAttestationException(it.message, it, IosAttestationException.Reason.CHALLENGE)
                    )

                is ch.veehait.devicecheck.appattest.attestation.AttestationException.InvalidReceipt -> {
                    var ex = it.cause
                    while (ex !is ReceiptException.InvalidPayload) {
                        if (ex == null) return AttestationException.Content.iOS(
                            cause = IosAttestationException(
                                cause = it,
                                reason = IosAttestationException.Reason.APP_UNEXPECTED
                            )
                        )
                        ex = ex.cause
                    }
                    if (ex.message?.startsWith("Receipt's creation time is after") == true)
                        AttestationException.Content.iOS(
                            cause = IosAttestationException(
                                cause = ex,
                                reason = IosAttestationException.Reason.STATEMENT_TIME
                            ),
                        )
                    else AttestationException.Content.iOS(
                        cause = IosAttestationException(
                            cause = it,
                            reason = IosAttestationException.Reason.APP_UNEXPECTED
                        )
                    )
                }
            }
        } else it as? AttestationException
            ?: AttestationException.Content.iOS(
                cause = IosAttestationException(
                    cause = it,
                    reason = IosAttestationException.Reason.APP_UNEXPECTED
                )
            )
    }


    inline fun <T : PublicKey, R> KeyAttestation<T>.foldTyped(
        onError: (AttestationResult.Error) -> R,
        onSuccess: (T, AttestationResult.Verified) -> R
    ): R = if (isSuccess) onSuccess(attestedPublicKey!!, details as AttestationResult.Verified)
    else onError(details as AttestationResult.Error)

    companion object {
        /**
         * Sane default to account for clock drifts seen in practice
         */
        val DEFAULT_TIME_OFFSET = 5.minutes

        /**
         * Nomen est omen; takes two durations in seconds (with the second one nullable) and returns the shorter one
         * as [Duration]
         */
        fun shortestDuration(firstInSeconds: Long, secondInSeconds: Long?): Duration =
            if (secondInSeconds == null) firstInSeconds.seconds
            else min(secondInSeconds, firstInSeconds).seconds

        /**
         * Nomen est omen; takes two durations in seconds (with the second one nullable) and returns the shorter one
         * as [Duration]
         */
        fun longestDuration(firstInSeconds: Long, secondInSeconds: Long?): Duration =
            if (secondInSeconds == null) firstInSeconds.seconds
            else max(secondInSeconds, firstInSeconds).seconds

        private fun shortestDurationInternal(firstInSeconds: Long?, secondInSeconds: Long?): Duration? {
            if (firstInSeconds == null && secondInSeconds == null) return null

            return if (secondInSeconds == null) shortestDuration(firstInSeconds!!, secondInSeconds)
            else shortestDuration(secondInSeconds, firstInSeconds)
        }

        private fun longestDurationInternal(firstInSeconds: Long?, secondInSeconds: Long?): Duration? {
            if (firstInSeconds == null && secondInSeconds == null) return null

            return if (secondInSeconds == null) longestDuration(firstInSeconds!!, secondInSeconds)
            else longestDuration(secondInSeconds, firstInSeconds)
        }

        /**
         * Version String of the current Warden Supreme release
         */
        val version: String = wardenVersion


        private val appAttestReader = ObjectMapper(CBORFactory())
            .registerKotlinModule()
            .readerFor(AttestationObject::class.java)
    }

    private class IosSetup(
        iosAttestationConfiguration: IosAttestationConfiguration,
        clock: Clock,
        verificationTimeOffset: Duration
    ) {
        val appAttestClock: java.time.Clock = java.time.Clock.offset(
            clock.toJavaClock(),
            verificationTimeOffset.toJavaDuration()
        )
        val iosApps: Map<IosAttestationConfiguration.AppData, AppleAppAttest> =
            iosAttestationConfiguration.applications.associateWith { appData ->
                AppleAppAttest(
                    app = App(appData.teamIdentifier, appData.bundleIdentifier),
                    appleAppAttestEnvironment = if (appData.sandbox) AppleAppAttestEnvironment.DEVELOPMENT else AppleAppAttestEnvironment.PRODUCTION,
                )
            }


        val attestationValidators: Map<AppleAppAttest, List<AttestationValidator>> =
            iosApps.map { (cfg, app) ->

                val anchors = cfg.trustedRootOverrides ?: iosAttestationConfiguration.trustedRoots
                app to anchors.map { trustAnchor ->
                    app.createAttestationValidator(
                        clock = appAttestClock,
                        receiptValidator = app.createReceiptValidator(
                            clock = appAttestClock,
                            maxAge = iosAttestationConfiguration.attestationStatementValiditySeconds.seconds.toJavaDuration(),
                            trustAnchor = trustAnchor.receiptRoot.trustAnchor
                        ),
                        trustAnchor = trustAnchor.attestationRoot.trustAnchor,
                    )
                }
            }.toMap()

        val iosVersion: IosAttestationConfiguration.OsVersions? = iosAttestationConfiguration.iosVersion
    }

}


private fun String.toBuildNumber(): BuildNumber = BuildNumber(this)
