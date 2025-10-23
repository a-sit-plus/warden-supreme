# Changelog

Since Warden Supreme is an evolution of WARDEN and continues to maintain and publish both WARDEN and WARDEN roboto as a dedicated artefacts,
this changelog also includes the original WARDEN changelog.

## Warden Supreme 1.0.0
* First-Class support for remote provisioning checks on Android
* Update `keyattestation to 2025-10-21`
* Update to Signum 3.18.0 / Supreme 0.10.0

## Warden Supreme 0.9.0
* Breaking change: `AttestationResult` hierarchy has been amended by a `Verified` subinterface
* Export Apple App Attest Validation library as API dependency
* Attach more context to Android exceptions
* Introduce dedicated callbacks for attestation errors and successes on the back-end
* Verify that Android patch levels are not too far in the future (default leeway: 1 month)
* More powerful `patchLevel`
* Dependency updates
    * Update conventions to 20250729
    * Update Kotlin to 2.2.20
    * Replace `kotlinx.datetime` with `kotlin.time`

### WARDEN 2.0.0
Breaking changes ahead!

- Parsing of iOS Build numbers in addition to OS Versions
    - Requires changes to configuration format
    - Introduces changes to IOS Attestation result
- Update to latest android-attestation
    - Changes types of ParsedAttestationRecord's properties
    - Exposes Guava as API dependency
- Update to latest conventions plugin
    - Kotlin 1.9.23
    - Publish version catalog
    - Depend on BC 1.77 strict
- Gradle 8.5

### 2.4.2
* Update to latest WARDEN-roboto, bringing Google's PKI cert path validator to guard against cert path validations
* Per-App trust anchor overrides
* BEHAVIOURAL CHANGE:
    * Android attestation errors due to certificate revocation don't fall into the `Content` exception category any more
    * Instead, they are now more correctly binned into the `Certificate.Trust` exception subtree
    * Per-App trust anchor overrides changes the order of checks on Android:
        * App-metadata checks are now performed first
        * Consequence: package, signature, … mismatches are reported even before certificate chain validation errors
* Kotlin 2.1.21
* Bouncy Castle 1.81
* KmmResult 1.9.3
* Signum 3.16.3
* Ktor 3.2.0


### 2.4.1
- Update to warden-roboto 1.8.1, allowing for ignoring Android attestation statement creation time
- Force specifying whether to ignore proxy settings for replaying debug attestation statements.

### 2.4.0 (Breaking binary configuration changes!)
- Update to WARDEN-roboto 1.8.0, which changes the Android configuration format to use `Long` instead of `Int` for temporal units in seconds
- To match WARDEN-roboto, the `attestationStatementValiditySeconds` iOS config has also been changed to `Long`
- Ability to record debug infos, serialize, deserialize and replay them
- Re-structure high-level attestation checks
- Dependency Updates
    * Kotlin 2.1.20
    * Kotlinx-Serialization 1.8.0
    * Ktor 3.0.3


### 2.3.3
- include latest WARDEN-roboto to work around upstream bug [#77](https://github.com/google/android-key-attestation/issues/77)
- Dependency Updates:
    - Ktor 3.0.3


### 2.3.2
* Fix documentation issue (Android version was missing a zero in all docs)
* Dependency Updates
    * WARDEN-roboto 1.7.1 (also fixing the same documentation issue)
    * Kotlin 2.1.0
    * Signum Indispensable 3.12.0
    * Bouncy Castle 1.79

### 2.3.1
* Fix wrong dependency

### 2.3.0: Behavioural Changes!
- Update to WARDEN-roboto 1.7.0
    - Android attestation statements (for SW, HW, but not Hybrid Nougat Attestation) do now verify attestation creation time!
    - Refer to the [WARDEN-roboto changelog](https://github.com/a-sit-plus/warden-roboto/blob/main/CHANGELOG.md#170)!
- Change Android verification offset calculation:  
  It is now the sum of the toplevel offset and the Android-specific offset
- Change the reason for iOS attestation statement temporal invalidity:
    - It is now `AttestationException.Content.iOS(cause = IosAttestationException(…, reason = IosAttestationException.Reason.STATEMENT_TIME))`
        - This reason was newly introduced in this release, making it binary and source incompatible!
    - iOS attestations are now also rejected if their validity starts in the future
    - The validity time can now be configured in the same way as for Android, using the `attestationStatementValiditySeconds` property
    - Any configured `verificationTimeOffset` is NOT automatically compensated for any more. This means if you have previously used a five minutes offset, you now have to manually increase the `attestationStatementValiditySeconds` to `10 * 60`!

### 2.2.0
- Introduce new attestation format

### 2.1.3
- Fix Parsing of iOS Build Numbers
- Dependency Updates:
    - Kotlin 2.0.20
    - Serialization 1.7.2

### 2.1.2
- Rely on [Signum](https://github.com/a-sit-plus/signum) to transcode public keys
- Add working `hashCode` and `equals` to `AttestationResult` and `KeyAttestation`
- Rework key attestation key comparison
    - Try all encodings for public keys
    - Throw exception with very detailed message when key attestation runs into a logical error

### 2.1.0
- Rebrand to WARDEN
- Dependency Updates
    - Update android-attestation 1.5.2 to WARDEN-roboto 1.6.0

### 2.0.2
- Dependency Updates:
    - Android-Attestation 1.5.2 with HTTP Proxy support for fetching revocation info
    - Java 17
    - Kotlin 2.0.0
    - bouncycastle: 1.78.1!!
    - coroutines: 1.8.1
    - datetime: 0.6.0
    - kmmresult: 1.6.1
    - kotest: 5.9.1!!
    - kotlin: 2.0.0
    - ksp: 1.0.22
    - ktor: 2.3.11
    - napier: 2.7.1
    - nexus: 1.3.0
    - serialization: 1.7.1

### 2.0.1
- Fix publishing
- Gradle 8.7

## WARDEN 1.0.0
This release introduces breaking changes as it allows multiple apps to be attested and introduces multi-stage
attestation on Android, please re-read the readme!

- Kotlin 1.9.10!
- Bouncy Castle 1.76
- Android-Attestation 1.0.0

###  1.5.0
- better iOS-specific exception handling and enumerable error cases
- Kotlin 1.9.22
- Various dependency updates including BC

####  1.4.5
- make fold function of KeyAttestation inline

####  1.4.4
- update android-attestation
- update gradle conventions

####  1.4.3
- update android-attestation

####  1.4.2
- fix temporal iOS receipt validation error not being propagated as such

####  1.4.1
- make all config classes data classes
- update to android attestation 1.2.1

###  1.4.0
- Discriminate between temporal certificate validation errors and trust-related ones

###  1.3.0
- Documentation updates
- Update to android-attestation 1.2.0
- Refactor exceptions

###  1.2.0
- introduce builder for AppData
- Introduce ByteArray.parseToPublicKey which takes ANSI X9.63 and DER-encoded byte arrays
  (only P-256 is supported for ANSI)
- Update android-attestation to 1.1.0

###  1.1.0
- remove verifyAttestation
- introduce verifyKeyAttestation taking an encoded public key as a byte array

## WARDEN 0.5.0
- Group OS-specific interfaces
- Align exception types between iOS and Android

###  0.5.6
- android-attestation 0.9.3
- better java interop

###  0.5.5 (java-interop impaired)
- android-attestation (0.9.2)

###  0.5.4 (broken!)
- fix dependency on wrong android-attestation version

###  0.5.3 (broken!)
- android-attestation updated
- use A-SIT Plus gradle conventions plugin
- Kotlin 1.9
- BC 1.75

###  0.5.2
- Kotlin 1.8.21
- Gradle 8.1.1
- depend on android-attestation 0.8.4 to support custom Android trust anchors and testing against software-created
  attestations.

###  0.5.1
- depend on android-attestation 0.8.3 (MR Jar)

## WARDEN 0.4
- ability to ignore timely validity of leaf cert for Android key attestation

###  0.4.1
- bugfix: NOOP attestation service actually being a NOOP

## WARDEN 0.3
Explicit verifyKeyAttestation function for both mobile platforms

###  0.3.3
- update upstream google code

###  0.3.2
- fixed iOS leeway calculation

###  0.3.1
- More Java-friendly API
- More detailed toplevel exception messages on certificate verification error (Android)
- Kotlin 1.8.0


## WARDEN 0.2
Reworked API and workflow to enable emulation of key attestation on iOS

## WARDEN 0.1
Initial Release