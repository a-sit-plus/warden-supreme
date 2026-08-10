package at.asitplus.attestation.android

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.toKmpCertificate


/**
 * Tries to parse an [AttestationKeyDescription] certificate extension, if present.
 * Never throws.
 */
val java.security.cert.X509Certificate.androidAttestationExtension: AttestationKeyDescription?
    get() = catchingUnwrapped {
        toKmpCertificate().getOrNull()?.androidAttestationExtension
    }.getOrElse {
        null
    }

@Deprecated("Unsafe behaviour", replaceWith = ReplaceWith("closestToRoot { it.hasAndroidKeyAttestationExtensionOid }.androidAttestationExtension"), DeprecationLevel.ERROR)
val List<java.security.cert.X509Certificate>.androidAttestationExtension: AttestationKeyDescription?
    get() = catchingUnwrapped {
        mapNotNull { it.toKmpCertificate().getOrNull() }.let {
            if (it.size != this.size) null else it.androidAttestationExtension
        }
    }.getOrElse {
        null
    }

val java.security.cert.X509Certificate.hasAndroidKeyAttestationExtensionOid: Boolean
    get() = nonCriticalExtensionOIDs?.contains(AttestationKeyDescription.oid.toString()) == true

@Deprecated(
    "Parses the extension. Use hasAndroidKeyAttestationExtensionOid to check only for its OID.",
    ReplaceWith("hasAndroidKeyAttestationExtensionOid"),
    DeprecationLevel.ERROR,
)
val java.security.cert.X509Certificate.hasAndroidKeystoreAttestation get() = androidAttestationExtension != null

/**
 * Returns a list of certificates that contain an attestation extension; in-order.
 *
 * @throws Throwable In case a certificate in the chain is malformed
 */
@Throws(Throwable::class)
fun List<java.security.cert.X509Certificate>.withAndroidAttestationExtensions(): List<java.security.cert.X509Certificate> =
    filter { it.toKmpCertificate().getOrThrow().androidAttestationExtension != null }

/**
 * Returns the certificate matching the predicate that is closes to the root. Can be the root itself.
 *
 * @throws Throwable if no match is found
 */
fun List<java.security.cert.X509Certificate>.closestToRoot(predicate: (java.security.cert.X509Certificate) -> Boolean) =
    last(predicate)

/**
 * Returns the certificate matching the predicate that is closes to the root. Can be the root itself
 */
fun List<java.security.cert.X509Certificate>.closestToRootOrNull(predicate: (java.security.cert.X509Certificate) -> Boolean) =
    catchingUnwrapped { closestToRoot(predicate) }.getOrNull()
