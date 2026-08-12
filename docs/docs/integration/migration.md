# Migration from WARDEN / WARDEN‑roboto

**The most visible change from WARDEN and WARDEN-roboto is the removal of Android Nougat hybrid attestation, which is no
longer relevant to supported deployments.**

!!! danger "Read This First: Footguns"
    The biggest upgrade hazards are about configuration loading and time checks:
    
    * Configuration loading should go through canonical config decoding. If you use Hoplite, add the `config-hoplite` module and register the provided `hopliteDecoder()`; **avoid Spring Boot's direct binding**. See [Externalising Configuration](config.md).
    * Android leaf certificate validity is ignored by default and Android attestation statement validity defaults to `null`; ensure freshness through your challenge/nonce handling. See [raw flow](raw.md).
    * Verification time offset now defaults to five minutes and is applied to certificate and attestation time checks on both platforms.
    * When migrating to Roboto's new `verify()` be sure to deal with the result. **This function does not throw!!!**
    
    **If you do not handle freshness explicitly, you can accidentally accept stale attestations.**

Warden Supreme enforces unified flows and a unified data model. Migration mostly means:

- Adopt the unified request/response envelopes and binding semantics from the Integration Guide.
- Move to the consolidated back‑end configuration (trust anchors, identities, policies).
- Keep your functionality via the integrated modules (_Warden makoto_ / _Warden roboto_); the legacy artefacts live under new names &mdash; see [Project Structure](structure.md).


!!! tip "TL;DR: What do I use now?"
    - **If you used WARDEN-roboto:** use **Warden roboto** (`at.asitplus.warden:roboto`) and the `Roboto` entry point.
    - **If you used WARDEN:** use **Warden makoto** (`at.asitplus.warden:makoto`) and the `Makoto` entry point.
    - **If you want the recommended end-to-end flow (client + verifier + unified wire format):** start with the [Integration Guide](supreme.md) (and its [data model](datamodel.md)).
    
    Cross-references:
    [Project Structure](structure.md) (where the modules live),
    [Usage without Integrated Clients](raw.md) (Makoto/Roboto directly),
    and [Externalising Configuration](config.md) (canonical config loading).

## Migrating to Warden Supreme 1.1+

!!! note 
    This section targets integrators coming from Warden Supreme 1.0.x.

The integrated transport is no longer unconditionally a signed CSR. New code uses `AttestationProof` end to end:

- `AttestationProof.Signed` wraps the existing complete CSR and preserves proof-of-possession behaviour.
- `AttestationProof.Hashed` wraps an unsigned TBS CSR whose canonical non-key, non-proof contents are authenticated
  through the platform attestation nonce.
- `AttestationChallenge.dataAuth` selects the required mode independently of optional `keyConstraints`.
- `AttestationChallenge.toBeAttestedAttributes` can request ordered required/optional client-provided values.

Update `AttestationClient.attest`, `AttestationVerifier.verifyAttestation`, `onChallengeValidated`,
`additionalVerifications`, and the certificate issuer to accept `AttestationProof`. The old CSR-only overloads are
deprecated compatibility paths: they continue to support signature authentication without requested attributes and reject
new semantics explicitly.

Use `AttestationVerifier.decodeAttestationProof(…)` at HTTP boundaries. It infers complete CSR versus TBS CSR from the ASN.1 shape,
without accepting a hash algorithm from the caller. The verifier obtains the expected mode and digest algorithm from the
matched challenge and rejects a submitted shape that does not match it.

## Changes (Makoto + Roboto APIs)
This section focuses on upgrades that keep using `Makoto` / `Roboto` directly, without adopting the integrated model.

### Names, Entry Points, and Flow
- Renames:
    - `Warden` → `Makoto`
    - `AndroidAttestationChecker` → `Roboto`.
- `Roboto` is now the primary Android verifier. It can validate hardware and/or software attestations depending on configuration (`disableHardwareAttestation`, `enableSoftwareAttestation`).
    - Legacy `HardwareAttestationVerifier` / `SoftwareAttestationVerifier` remain as deprecated compatibility factories that return a `Roboto` instance.
- Makoto can be configured for Android‑only or iOS‑only verification; attestations received from non‑configured platforms are treated as configuration errors. See [Error Handling](errorhandling.md).
- Roboto exposes a `KmmResult`-based verification API:
    - use `verify(...)` (suspending) or `verifyBlocking(...)` (blocking), and optionally chain `getOrThrow()`. The legacy `verifyAttestation(...)` API (returning `ParsedAttestationRecord`) is deprecated.
    - On success the result will contain the full certificate chain, on failure, it will contain an  `AndroidAttestationException`.
    - **Be sure to deal with the result. This function does not throw!!!**
- The parameters `iosAttestationConfigurationJ` and `androidAttestationConfigurationJ` in `Makoto`'s Java-oriented constructor have been swapped to disambiguate it from the Kotlin constructors.


### Results and Exceptions

!!! tip "Try the custom parser"
    To enable the custom Android attestation extension parser, set `supremeParser = true` in your configuration and run your usual `Roboto`/`Makoto` verification flow.

- `AttestationResult` gains a `Verified` marker; NOOP results are distinct.
- `AttestationResult.Error` always carries a `cause`.
- `AttestationValueException.Reason.TIME` is renamed to `STATEMENT_TIME`.
- Non-configured platforms return `AttestationResult.Error` with a configuration cause. See [Error Handling](errorhandling.md).
- Roboto verification now returns the verified certificate chain (`List<X509Certificate>`) wrapped in `KmmResult`. Downstream code should parse the extension from the resulting chain via `androidAttestationExtension` (preferred).
    - **Be sure to deal with the result. This function does not throw!!!**
- `ParsedAttestationRecord` is considered legacy: it is still accessible via deprecated helpers (e.g. `AttestationResult.Android.attestationRecord`), but new code should use `AttestationResult.Android.attestationExtension` / `androidAttestationExtension`.
- The `supremeParser` flag selects which verification engine/parser is used internally; it no longer changes the public return type.

### Time Handling and Validity
- Verification time offset defaults to five minutes and is applied to certificate and attestation time checks.
- iOS attestation validity now uses the same `attestationStatementValiditySeconds` model as Android and rejects future‑dated statements.
- iOS verification time offset is no longer auto‑compensated, but the new defaults take this into account; increase `attestationStatementValiditySeconds` if you relied on the old behavior.
- Android leaf certificate validity is ignored by default; Android's `attestationStatementValiditySeconds` defaults to `null` (no statement time check). If configured, Android attestation creation time is verified.
- Roboto’s Kotlin APIs use `kotlin.time.Instant` as the verification time; Java-friendly overloads accept `java.util.Date` and Java's `Instant`.
- Patch level checks reject patch levels too far in the future (default leeway: one month).

### Revocation, Trust Anchors, and RKP
- Revocation checks are configurable and chainable (HTTP/file/in‑memory loaders) and return richer details.
- Revocation errors are classified under certificate trust errors rather than content errors and include the revocation list entry.
- Per‑app trust anchor overrides change the order of checks so app metadata is validated before certificate chain validation. See [Android technical notes](../technical/android.md).
- Remote Key Provisioning checks are supported and can be required; failure yields a dedicated value error. See [Android technical notes](../technical/android.md).

See also the [data model](datamodel.md), [Error Handling](errorhandling.md), and the authoritative configuration example in the [Warden Supreme integration guide](supreme.md#config-options-example).


## Externalising Configuration

!!! tip inline end "List of Configuration Properties"
    See [Externalising Configuration](config.md) for an up-to-date list of all configuration properties.


The compiler and IDE identify most source changes required when migrating from WARDEN or WARDEN-roboto. Externalised
configuration requires more care.

Warden Supreme 1.0 introduces canonical serialised representations of the Android- and iOS-specific attestation configurations.
Previously, Spring Boot and Hoplite could load configurations directly.
The new flexibility around Android revocation checks means that verifying and sanity-checking externalised configuration
now only works through code paths that are part of Warden Supreme.
So load configurations only through one of the following functions (or via Hoplite with the decoder from `config-hoplite`, or via the `config-spring` module):

* `fromJsonString()`
* `fromYamlString()`
* `fromJsonObject()`
* `fromJsonFile(...)` / `fromYamlFile(...)` (JVM convenience helpers)

So a Spring Boot configuration should hold a string pointing to your Warden Supreme configuration files; read those files
and feed their contents into `fromYamlString()`. Alternatively, Spring Boot users can use the `config-spring` module for
native Spring config loading. (Under the hood, this pushes an `Environment` into the same `fromJsonObject()` codepath,
which avoids direct binding while still allowing native Spring configuration sources.)  
For Hoplite, register `hopliteDecoder()` (from the `config-hoplite` module) and load from your chosen sources; it delegates
into `fromJsonObject()`.


### Configuration Differences
Aside from config loading, some configuration parameters and defaults changed between the last stable WARDEN /
WARDEN-roboto releases and Warden Supreme 1.0.0.

- **Android:**
    * Trust anchors are now `TrustedRoot`s and are split into `hardwareTrustedRoots` / `softwareTrustedRoots`. See [Externalising Configuration](config.md) and [Android technical notes](../technical/android.md).
    * Per‑app trust anchor overrides moved to `AppData.trustedRootOverrides`.
    * `signatureDigests` is now `signerFingerprints`.
    * `attestationStatementValiditySeconds` uses `Long` and can be `null`.
- **iOS:**
    * iOS versions now require both SemVer and build number (`OsVersions`). See [Externalising Configuration](config.md) and [iOS technical notes](../technical/ios.md).
    * Per‑app trust anchor overrides use `TrustedRootPair`.



!!! info "Need more migration depth?"
    If you require a step‑by‑step migration playbook or have edge cases not covered here, please [file an issue](https://github.com/a-sit-plus/warden-supreme/issues/new)
    or upvote an existing one in the tracker so we can prioritise expanding this guide.
    
    If you need personalised support, see our [&nbsp;💎 Services](../services.md).
