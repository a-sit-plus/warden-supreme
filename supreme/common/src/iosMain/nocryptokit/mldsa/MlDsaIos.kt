package at.asitplus.attestation.supreme.mldsa

// Non-macOS hosts cannot build the CryptoKit shim (see build.gradle.kts). iOS then only gets the ASN.1 support
// registered in commonMain: ML-DSA keys and signatures can be encoded, decoded and transported, but not created.
internal actual fun installPlatformMlDsa() {}
