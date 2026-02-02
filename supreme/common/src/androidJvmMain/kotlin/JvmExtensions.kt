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

val List<java.security.cert.X509Certificate>.androidAttestationExtension: AttestationKeyDescription?
    get() = catchingUnwrapped {
        mapNotNull { it.toKmpCertificate().getOrNull() }.let {
            if (it.size != this.size) null else it.androidAttestationExtension
        }
    }.getOrElse {
        null
    }