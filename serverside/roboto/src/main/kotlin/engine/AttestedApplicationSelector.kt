package at.asitplus.attestation.android.engine

import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.attestation.android.hasAndroidKeyAttestationExtensionOid
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1ExplicitlyTagged
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.parse
import com.google.android.attestation.Constants.KEY_DESCRIPTION_OID
import java.nio.charset.StandardCharsets.UTF_8
import java.security.cert.X509Certificate

/** Reads only the bounded application identity needed to choose an app-specific trust policy. */
internal fun List<X509Certificate>.selectAttestedApplication(
    applications: List<AndroidAttestationConfiguration.AppData>,
): AndroidAttestationConfiguration.AppData? {
    val certificate = lastOrNull { it.hasAndroidKeyAttestationExtensionOid } ?: return null
    val extension = certificate.getExtensionValue(KEY_DESCRIPTION_OID) ?: return null
    return selectAttestedApplication(extension, applications)
}

internal fun selectAttestedApplication(
    extension: ByteArray,
    applications: List<AndroidAttestationConfiguration.AppData>,
): AndroidAttestationConfiguration.AppData? {
    require(extension.size <= MAX_EXTENSION_BYTES) { "Attestation extension is too large" }

    val keyDescriptionBytes = Asn1Element.parse(extension).asOctetString().content
    val keyDescription = Asn1Element.parse(keyDescriptionBytes).asSequence()
    require(keyDescription.children.size == KEY_DESCRIPTION_FIELD_COUNT) { "Invalid key description" }
    val appIdTags = keyDescription.children[SOFTWARE_ENFORCED_INDEX].asSequence().children
        .filterIsInstance<Asn1ExplicitlyTagged>()
        .filter { it.tag == Asn1.ExplicitTag(ATTESTATION_APPLICATION_ID_TAG) }
    require(appIdTags.size <= 1) { "Duplicate attestation application ID" }
    val appIdTag = appIdTags.singleOrNull()
        ?: return null
    val appId = appIdTag.children.singleOrNull()?.asOctetString()?.content
        ?: return null
    require(appId.size <= MAX_APPLICATION_ID_BYTES) { "Attestation application ID is too large" }

    val fields = Asn1Element.parse(appId).asSequence().children
    require(fields.size == APPLICATION_ID_FIELD_COUNT) { "Invalid attestation application ID" }
    val packages = fields[0].asSet().children
    val digests = fields[1].asSet().children
    require(packages.size <= MAX_PACKAGE_COUNT) { "Too many attestation packages" }
    require(digests.size <= MAX_DIGEST_COUNT) { "Too many attestation signature digests" }

    val packageMatches = applications.filter { app ->
        packages.any { packageInfo ->
            val values = packageInfo.asSequence().children
            if (values.size != PACKAGE_INFO_FIELD_COUNT) return@any false
            val name = values[0].asOctetString().content
            values[1].asPrimitive()
            name.size <= MAX_PACKAGE_NAME_BYTES && String(name, UTF_8) == app.packageName
        }
    }
    if (packageMatches.isEmpty()) throw AttestationValueException(
        "Invalid Application Package",
        reason = AttestationValueException.Reason.PACKAGE_NAME,
        expectedValue = applications.map { it.packageName },
        actualValue = null,
    )
    return packageMatches.firstOrNull { app ->
        digests.any { digest ->
            digest.overallLength <= MAX_DIGEST_BYTES + 2 /*we know that this must be a short octet string, so +2 bytes*/
                    && app.signerFingerprints.any { it.contentEquals(digest.asOctetString().content) }
        }
    } ?: throw AttestationValueException(
        "Invalid Application Signature Digest",
        reason = AttestationValueException.Reason.APP_SIGNER_DIGEST,
        expectedValue = packageMatches.flatMap { it.signerFingerprints },
        actualValue = null,
    )
}

private const val SOFTWARE_ENFORCED_INDEX = 6
private const val KEY_DESCRIPTION_FIELD_COUNT = 8
private const val APPLICATION_ID_FIELD_COUNT = 2
private const val PACKAGE_INFO_FIELD_COUNT = 2
private const val ATTESTATION_APPLICATION_ID_TAG = 709uL
private const val MAX_EXTENSION_BYTES = 64 * 1024
private const val MAX_APPLICATION_ID_BYTES = 32 * 1024
private const val MAX_PACKAGE_COUNT = 32
private const val MAX_DIGEST_COUNT = 64
private const val MAX_PACKAGE_NAME_BYTES = 255
private const val MAX_DIGEST_BYTES = 128
