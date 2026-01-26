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
    }.getOrNull()