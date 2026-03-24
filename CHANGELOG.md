# Changelog

Since Warden Supreme is an evolution of WARDEN and continues to maintain and publish both WARDEN and WARDEN roboto as
dedicated artefacts,
this changelog also includes the original WARDEN changelog.

# NEXT
* Features
    * Support custom verified boot keys
        * Allows treating self-signed just like a locked bootloader if desired
        * Makes it possible to disallow even OEM ROMS and allow only GrapheneOS, for example
* API Changes:
    * Signer fingerprints is now a `Set` and not a list anymore
* Behavioural Changes:
    * `parseHex` now also strips `:` by default

# 1.0.0-RC5
* Features
    * Proper iOS assertion validation (thanks @andreybogdanov-sprind!)
    * Serializers and ASN.1 codec for `ValidatedAttestation`
    * Move `AttestationConfiguration` helpers into `supreme-common`.
    * Add `config-hoplite` module that provides `hopliteDecoder()` for all `AttestationConfiguration` readers.
    * Add **experimental** `config-spring` module that binds Spring Boot config loading to the canonical serialization path.
    * YAML polymorphic configs now use a flat `type` shape (matching JSON) while still accepting legacy `type`/`value` YAML on decode.
* Fixes
    * Expose Kotlin-Stdlib as API dependency to make integration with Java projects smoother 
* Tests
    * Extend configuration round-trip tests to include Hoplite loading and legacy YAML fixtures.
* API Changes:
    * rename `AttestationService.ios.verifyAssertion` -> `AttestationService.ios.verifyCombined` and deprecate the old function 
* Dependency Updates
    * Update upstream attestation library to 9066c0a003225e776b93ba5906d46c45904173de

# 1.0.0-RC3
* Features:
    * Get Attestation extension from certificate chain (same as Google's parser: return the attestation extension closest to the root)
    * Rework custom Attestation extension parser 
        * Now list-based to handle arbitrary properties
        * Add missing properties to custom parser
        * Expose known properties as getters from this list
        * Custom Parser correctly handles UserAuthType and many more
        * -> **Warden Supreme now parses more Attestation extensions correctly than Google's shiny new parser AND with better semantics and Debugging**
        * Add `attestationExtension` shorthand to `AttestationResult`, returning an `AttestationKeyDescription`
    * Refactor Roboto
        * `Roboto` changes from abstract base class to a concrete wired based on config (experimentalParser, HW/SW toggles)
        * Delegate actual checks to `Engines` to prepare replacing Google's parser and PKIX cert path validator  
          (set `experimentalParser = true` in config to try it out)
        * Deprecate old blocking verification function that was tied to Google's old parser
        * Introduce new suspending verification function
            * Returns a `KmmResult<List<X509Certificate>>`
            * Never throws
        * **First preview of attestation checks based on own parser**
* Fixes:
    * Relax the upstream parser to glitch out less often
        * -> **Warden Supreme now parses more Attestation extensions than WARDEN-roboto ever could.**
    * Correctly re-encode cursed X.509 certificate extensions that encode `critical=true` instead of omitting it
    * Artefacts don't need `google()` maven repo any more
    * No mire init crash in Java projects using Warden Supreme
* API-Changes:
    * Roboto refactor 
        * Directly instantiate Roboto (see "Refactor Roboto")
        * Roboto's functions now expect Kotlin `Instant` instead of Java `Date`
        * Blocking functions have been made extensions instead of members
        * Java-compatible signature remain
        * `HardwareAttestationVerifier` / `SoftwareAttestationVerifier` are no longer classes
            * Now they are deprecated factory objects returning a `Roboto` instance
    * Weed out half-baked `AttestationValue` functions and add mappings from/to (Kmm)Result
    * Weed out half-baked `AttestationValue` functions and add mappings from/to (Kmm)Result
* Revised and expanded documentation
* Dependency Updates:
    * Signum 3.19.3 / Supreme 0.11.3


# 1.0.0-RC2
* Features:
    * Relax custom parser to report less values as error
    * Add extension to read/write configurations directly from/to files
* Fixes:
    * Correct generation of API docs 
    * Support cursed RSA PKCS1 X.509 signature algorithm profiles used by one of the larges OEMs
* Revised and extended documentation
* Dependency Updates:
    * Signum 3.19.2 / Supreme 0.11.2


# 1.0.0-RC
**Release Candidate for Warden Supreme 1.0.0**

**Critical fix (integrated flow):**  
Warden Supreme (and its predecessors WARDEN and WARDEN-roboto) always correctly validated attestation.
However, earlier Warden Supreme builds had a bug in the **proof-of-possession check for the client private key** (signature verification).
This only affected the fully integrated ("Supreme") flow (implemented in `AttestationVerifier`).  
**Roboto and Makoto were never affected** since neither did proof-of-possession checks.

**If you use `AttestationVerifier` (the integrated flow), update to this release. If you use Roboto and/or Makoto directly, you are not affected.**

* **New Features**
    * Make it possible to configure only iOS or only Android attestation
        * `AttestationResult.Error.CONTENT` is now thrown when an attestation is received for a non-configured platform
    * Ability to set the clock on the client for testing/debugging (only sensible on Android)
    * Add custom Android Attestation Extension parser (for debugging purposes, for now)
    * Revamp AttestationChallenge
        * Configurable device name OID
            * Replace `includeGenericDeviceName` in favour of `genericDeviceNameOID`
            * Old constructor signatures have been removed
            * Also affects `AttestationVerifier`
        * Bump challenge version to `2`
    * Revamp challenge validation API to take the full CSR from the client instead of just the nonce already extracted from it
    * Introduce canonical config format to avoid issues with config loading
        * Discourage config loading through Hoplite or Spring Boot
        * Includes YAML and JSON format
        * Docs include auto-generated full JSON and YAML as a reference
    * Completely revamped Android revocation checks based on configurable, chainable loaders
        * Allows specifying custom revocation lists
        * Allows disabling revocation checks altogether
        * Extensible with custom loaders
        * Included loaders:
            * HTTP-based, caching
                * Supports SOCKS and HTTP proxies
            * File-based, caching
            * In-memory, static, non-caching
    * Provide fully-fledged Android revocation lists
        * The Android-specific `Revoked` error now includes the revocation list entry that indicates a revocation or suspension.
    * Debugging is now smoother because debug statements now include the snapshot of the revocations lists they have been using 
* **Fixes**
    * **Fix a proof-of-possession (client private key) verification bug in the Supreme integrated `AttestationVerifier` flow**
        * **Attestation verification was always correct; only proof-of-possession was affected**
        * **Neither Roboto nor Makoto were ever affected by this**
    * Per-App Strongbox overrides are now respected
    * Fix custom auth prompts not propagating for fully integrated flows
    * Fix per-app trust anchors not being picked up when using the config builders.
    * Allow specifying CSR attributes and extensions for fully integrated flows
    * Fix nonce validity duration calculation
    * Additional fixes to exception equality checks
* **Removed Features**
   * Nougat Hybrid Attestation has been completely removed due to irrelevance
       * Android 7 was released a decade ago
       * Devices released with Android 7 it lost support around eight years ago
* **API-only Changes**
    * Remove all deprecations marked for removal with 1.0.0.
    * Switch order of `androidAttestationConfigurationJ` and `iosAttestationConfigurationJ` for Java-oriented Makoto constructor
    * Remove ability to specify challenge validity as instant
        * Validity is set as a duration
        * read-only `validUntil` Instant-property stays
    * Make Content exception a sealed class
    * Rename `AttestationValueException.Reason.TIME` -> `AttestationValueException.Reason.STATEMENT_TIME`
    * AttestationResult.Error will now always contain a `cause`
    * Make attestation functions suspending and provide blocking wrappers under old `@JvmName`s
    * Make Makoto configs publicly accessible
    * Deprecate misnamed and overly complex APIs. They will be removed with 1.1
    * Fail early on invalid iOS team identifier length
    * Android-only debug statements must now also contain a version number
    * Add `onChallengeValidated` callback to `AttestationVerifier.verifyAttestation`
    * Make `verifyAttestation` callbacks suspending and ignore callback exceptions
* **Dependency and Build updates**
    * Gradle 9 + Kotlin 2.3
        * Return value checker defaults to `check`
    * Dependency updates:
        * Dokka 2.10.0  
        * AGP 8.12.3
        * Ktor 3.3.3
        * Bouncy Castle 1.83 (no more forcing exact version)
        * Android Key Attestation Check lib from Google b5176b4d3fdd97301be0d194ab48ab3c6fa558fb


## 0.9.9999.1
* Fix missing old HW trust anchor

## 0.9.9999
* Fix infinite recursion on clock conversion
* Integration tests with default validity periods
* Fix wrong offset sign with secondary `AttestationVerifier` constructor
* Rework NOOP attestation and NOOP results
    * Non-error AttestationResults now come with an `AttestationResult.Kind` marker interface
    * Makoto produces `AttestationResult.Verified`
    * NoopAttestationService produces `AttestationResult.NOOP`
    * `KeyAttestation.fold` now produces a nullable `AttestationResult.Verified` on success to acccount for NOOP results
    * Makoto and NoopAttestationService bring their own `foldTyped` extenstion (which sadly cannot override a common abstract extension, because they need to be inline)
* Make `makoto` property of `AttestationVerifier` public
* Versioned debug statements

## 0.9.999
* Quality of life improvements:
    * Truly, fully integrated attestation flows in a single line of client code
    * Ability to set an auth prompt text and cancel message for integrated flows
    * Various documentation fixes
* Force allow signing
* Add schemas to docs
* Fix `supreme-commons` build setup

## 0.9.99

This release introduces breaking changes to the integrated ("Supreme") components to deliver **truly, fully integrated
key and app attestation**, pinning down the last unnecessarily moving parts:

* Rename `AttestationValidator` -> `AttestationVerifier` to align with wording (and introduce typealias, but marked as deprecated)
* Rename `verifyKeyAttestation` -> `verifyAttestation` (and introduce delegate, but marked as deprecated)
    * `CertificateIssuer` now has `AttestationResult.Verified` as receiver for the new function.
    * The deprecated function stays as it is.
* Allow `CertificateIssuer` to throw instead of returning a `KmmResult`
* Constrain challenge issuing wrt. validity duration: No more params can be specified, but informational adding of time zone is still allowed.

**It also includes behavioural changes to the Android and iOS attestation defaults:**

* Don't allow negative validity durations
* Ignore Android leaf cert validity by default, because Warden Supreme, by default, uses random cryptographic nonces.
    * `ingoreLeafValidity()` (yes, with typo!) function of the `AndroidAttestationConfiguration.Builder` is now a deprecated NOOP to be removed.
    * `enforceLeafValidity()` (without typo!) function was introduced
* Android `attestationStatementValiditySeconds` defaults to `null`, because Warden Supreme, by default, uses random cryptographic nonces.
* iOS clock verification time offset defaults to five minutes, which are added to the attestation statement validity by default.
* Rename `Warden` -> `Makoto` to more clearly distinguish individual components by name
    * A `typealias Warden = Makoto` is present, but marked as deprecated
* Rename `AndroidAttestationChecker` -> `Roboto` to more clearly distinguish individual components by name
    * Rename `HardwareAttestationChecker` -> `HardwareAttestationVerifier` (and introduce typealias, but marked as deprecated) 
    * Rename `NougatHybridAttestationChecker` -> `NougatHybridAttestationVerifier` (and introduce typealias, but marked as deprecated) 
    * Rename `SoftwareAttestationChecker` -> `SoftwareAttestationVerifier` (and introduce typealias, but marked as deprecated)
* Android total validity offset is now more lenient and simply checked for overflows
* **If all parameters are configured explicitly, nothing changes, except for some renames**

**New features:**

* Ship a default OID to identify the attestation proof.
* Add defaults for keyConstraints and nonce validity duration &rarr; Fully integrated key and attestation generation
* Transmit device names inside CSR on a best-effort basis
* Per-App StrongboxOverride
* Expose Makoto `verificationTimeOffset` and `clock`, `shortestValidityDuration`
* Rework Trust Anchor Management:
    * Introduce `TrustedRoot` interface to represent trust anchors
        * `TrustedRoot.Certificate` for certificates
        * `TrustedRoot.PublicKey` for using raw public keys, optionally specifying a CA name
            * No CA name -> no CA name check
            * CA name set -> CA name check
    * Android trust anchors can now be certificates or public keys thanks to `TrustedRoot`
        * Default hardware attestation trust anchors are available in `GOOGLE_DEFAULT_HARDWARE_TRUST_ANCHORS`
        * Default software attestation trust anchors for Android <=11 are available in
          `GOOGLE_SOFTWARE_TRUST_ANCHORS_UNTIL_A11`
    * iOS now also supports setting custom trust anchors (currently certificates only) via
        * `trustedRoots` config property
        * `trustedRootOverrides` for app-specific overrides
        * `overrideTrustedRoots` for the builder
        * Defaults trusted roots are available in `APPLE_DEFAULT_TRUSTED_ROOTS`
    * Default android trust anchors are now all the attestation certificates, not just a raw public key
    * Existing function signatures and constants are preserved for compatibility **but will be removed in the next major
      release**
    * Android configuration migration guide (iOS only got added functionality):
        * `hardwareAttestationTrustAnchors` -> `hardwareTrustedRoots`
        * `softwareAttestationTrustAnchors` -> `softwareTrustedRoots`
        * `AppData.overrideTrustAnchors` -> `AppData.trustedRootOverrides`
        * `AppData.trustAnchorOverrides` -> `AppData.trustedRootOverrides`
        * `AppData.signatureDigests` -> `AppData.signerFingerprints`
* Consistent configuration Builder API functions
    * `overrideXXX(s)` -> `XXXoverride(s)`

## Warden Supreme 0.9.1

* First-Class support for remote provisioning checks on Android
* API CHANGE: `CerfificateIssuer` Lambda now also has access to the full attestation result
* FIX: [challenge validity checks](https://github.com/a-sit-plus/warden-supreme/issues/4)
* Added new Google HW root signing key
* Dependency Updates
    * `keyattestation` to 2025-10-21
    * Signum 3.18.2 / Supreme 0.10.2
    * Guava 33.5.0-jre
    * gson 2.13.2
    * errorprone 2.43.0
    * protobuf 4.33.0

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

- Update to WARDEN-roboto 1.8.0, which changes the Android configuration format to use `Long` instead of `Int` for
  temporal units in seconds
- To match WARDEN-roboto, the `attestationStatementValiditySeconds` iOS config has also been changed to `Long`
- Ability to record debug infos, serialize, deserialize and replay them
- Re-structure high-level attestation checks
- Dependency Updates
    * Kotlin 2.1.20
    * Kotlinx-Serialization 1.8.0
    * Ktor 3.0.3

### 2.3.3

- include latest WARDEN-roboto to work around upstream
  bug [#77](https://github.com/google/android-key-attestation/issues/77)
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
    - Android attestation statements (for SW, HW, but not Hybrid Nougat Attestation) do now verify attestation creation
      time!
    - Refer to the [WARDEN-roboto changelog](https://github.com/a-sit-plus/warden-roboto/blob/main/CHANGELOG.md#170)!
- Change Android verification offset calculation:  
  It is now the sum of the toplevel offset and the Android-specific offset
- Change the reason for iOS attestation statement temporal invalidity:
    - It is now
      `AttestationException.Content.iOS(cause = IosAttestationException(…, reason = IosAttestationException.Reason.STATEMENT_TIME))`
        - This reason was newly introduced in this release, making it binary and source incompatible!
    - iOS attestations are now also rejected if their validity starts in the future
    - The validity time can now be configured in the same way as for Android, using the
      `attestationStatementValiditySeconds` property
    - Any configured `verificationTimeOffset` is NOT automatically compensated for any more. This means if you have
      previously used a five minutes offset, you now have to manually increase the `attestationStatementValiditySeconds`
      to `10 * 60`!

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

### 1.5.0

- better iOS-specific exception handling and enumerable error cases
- Kotlin 1.9.22
- Various dependency updates including BC

#### 1.4.5

- make fold function of KeyAttestation inline

#### 1.4.4

- update android-attestation
- update gradle conventions

#### 1.4.3

- update android-attestation

#### 1.4.2

- fix temporal iOS receipt validation error not being propagated as such

#### 1.4.1

- make all config classes data classes
- update to android attestation 1.2.1

### 1.4.0

- Discriminate between temporal certificate validation errors and trust-related ones

### 1.3.0

- Documentation updates
- Update to android-attestation 1.2.0
- Refactor exceptions

### 1.2.0

- introduce builder for AppData
- Introduce ByteArray.parseToPublicKey which takes ANSI X9.63 and DER-encoded byte arrays
  (only P-256 is supported for ANSI)
- Update android-attestation to 1.1.0

### 1.1.0

- remove verifyAttestation
- introduce verifyKeyAttestation taking an encoded public key as a byte array

## WARDEN 0.5.0

- Group OS-specific interfaces
- Align exception types between iOS and Android

### 0.5.6

- android-attestation 0.9.3
- better java interop

### 0.5.5 (java-interop impaired)

- android-attestation (0.9.2)

### 0.5.4 (broken!)

- fix dependency on wrong android-attestation version

### 0.5.3 (broken!)

- android-attestation updated
- use A-SIT Plus gradle conventions plugin
- Kotlin 1.9
- BC 1.75

### 0.5.2

- Kotlin 1.8.21
- Gradle 8.1.1
- depend on android-attestation 0.8.4 to support custom Android trust anchors and testing against software-created
  attestations.

### 0.5.1

- depend on android-attestation 0.8.3 (MR Jar)

## WARDEN 0.4

- ability to ignore timely validity of leaf cert for Android key attestation

### 0.4.1

- bugfix: NOOP attestation service actually being a NOOP

## WARDEN 0.3

Explicit verifyKeyAttestation function for both mobile platforms

### 0.3.3

- update upstream google code

### 0.3.2

- fixed iOS leeway calculation

### 0.3.1

- More Java-friendly API
- More detailed toplevel exception messages on certificate verification error (Android)
- Kotlin 1.8.0

## WARDEN 0.2

Reworked API and workflow to enable emulation of key attestation on iOS

## WARDEN 0.1

Initial Release
