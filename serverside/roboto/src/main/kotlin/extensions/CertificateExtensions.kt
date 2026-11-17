package at.asitplus.attestation.android

import at.asitplus.catchingUnwrapped
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.encoding.parse
import co.nstant.`in`.cbor.CborDecoder
import com.android.keyattestation.verifier.provisioningInfo
import java.security.cert.X509Certificate
import javax.security.auth.x500.X500Principal


import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.asn1
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.encoding.decodeToString
import co.nstant.`in`.cbor.model.UnsignedInteger
import com.android.keyattestation.verifier.asInteger

@JvmName("getSignumRkpData")
fun List<Certificate>.getRkpData(): co.nstant.`in`.cbor.model.Map? = catchingUnwrapped {
    require(isRemoteKeyProvisioned())
    get(1).tbsCertificate.extensions.firstOrNull { it.oid == ObjectIdentifier(OID_RKP) }?.let {
        CborDecoder.decode(it.asn1.toRepresentation().value).first() as co.nstant.`in`.cbor.model.Map
    }
}.getOrNull()

@JvmName("getSignumNumberOfRemotelyProvisionedCertificates")
fun List<Certificate>.getNumberOfRemotelyProvisionedCertificates(): Int? = catchingUnwrapped {
    requireNotNull(getRkpData()?.get(UnsignedInteger(1L))).asInteger()
}.getOrNull()

@JvmName("isSignumRemoteKeyProvisioned")
fun List<Certificate>.isRemoteKeyProvisioned(): Boolean {
    if (size < 2) return false
    val attributes = get(size - 2).tbsCertificate.subjectName.relativeDistinguishedNames
        .flatMap { it.attrsAndValues }
        .filter { it.oid == AttributeTypeAndValue.OID.commonName || it.oid == AttributeTypeAndValue.OID.organizationName }
        .associate { it.oid to it.asn1.toRepresentation().value.asPrimitive().decodeToString() }
    return attributes[AttributeTypeAndValue.OID.commonName] == "Droid CA2" &&
        attributes[AttributeTypeAndValue.OID.organizationName] == "Google LLC"
}

/**
 * Returns the parsed, but generic contents of the [Remote Key Provisioning
 * extension](https://source.android.com/docs/security/features/keystore/attestation#provisioninginfo_extension),
 * if present in an Android attestation certificate chain.
 * One would assume that we could define a type-safe data structure for that, but Samsung being Samsung
 * has kindly reminded us of the fact that phrases like "conforms schema" are thrown around far too often in specifications.
 *
 * Google's code has such a type for that, but I wouldn't trust vendors to observe the CBOR schema,
 * so we just check for valid CBOR as a baseline.
 *
 * @see provisioningInfo to get the number of issued certificates
 */
fun List<X509Certificate>.getRkpData(): co.nstant.`in`.cbor.model.Map? = catchingUnwrapped {
    require(isRemoteKeyProvisioned())
    get(1).getExtensionValue(OID_RKP)?.let {
        val rkpData = CborDecoder.decode(Asn1Element.parse(it).asOctetString().content)
        rkpData.first() as co.nstant.`in`.cbor.model.Map
    }
}.getOrNull()

/**
 * **TRIES** to parse the number of remotely provisioned attestation certificates.
 * Note that this method returning `null` does not necessarily mean that a remotely provisioned
 * certificate is not present. It could very well be that the extension is present but botched.
 * (Looking at you, Samsung!).
 *
 * @see isRemoteKeyProvisioned
 */
fun List<X509Certificate>.getNumberOfRemotelyProvisionedCertificates(): Int? = catchingUnwrapped {
    require(isRemoteKeyProvisioned())
    get(1).provisioningInfo()?.certificatesIssued
}.getOrNull()

/**
 * Indicates whether the attestation certificate in this certificate chain is remotely provisioned.
 *
 * This snippet incorporates [code](https://github.com/android/keyattestation/blob/main/src/main/kotlin/provider/KeyAttestationCertPath.kt#L119) from Google's CertPathValidator
 */
fun List<X509Certificate>.isRemoteKeyProvisioned(): Boolean {
    if (size < 2) return false
    val principal = get(size - 2).subjectX500Principal
    val rdn = parseDN(principal.getName(X500Principal.RFC1779))
    return rdn["CN"] == "Droid CA2" && rdn["O"] == "Google LLC"
}

//taken from https://github.com/android/keyattestation/blob/main/src/main/kotlin/provider/KeyAttestationCertPath.kt#L143C1-L154C2 as it is private in the incorporated code
private fun parseDN(dn: String): Map<String, String> {
    val attributes = mutableMapOf<String, String>()
    val parts = dn.split(",")

    for (part in parts) {
        val keyValue = part.trim().split("=", limit = 2)
        if (keyValue.size == 2) {
            attributes[keyValue[0].trim()] = keyValue[1].trim()
        }
    }
    return attributes
}
