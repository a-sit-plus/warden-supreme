# Migration from WARDEN / WARDEN-roboto

**The most obvious change coming from WARDEN / WARDEN-roboto is dropped support for Nougat hybrid attestation on Android. It is simply not relevant any more.**

!!! danger "Read This First: Footguns"
    The biggest upgrade hazards are about configuration loading and time checks:
    
    * Configuration loading through Hoplite/Spring Boot is no longer supported and can silently misconfigure checks. Use canonical config loading only. See [Externalising Configuration](config.md).
    * Android leaf certificate validity is ignored by default and Android attestation statement validity defaults to `null`; ensure freshness through your challenge/nonce handling. See [raw flow](raw.md).
    * Verification time offset now defaults to five minutes and is applied to certificate and attestation time checks on both platforms.
    
    **If you do not handle freshness explicitly, you can accidentally accept stale attestations.**

Warden Supreme enforces unified flows and a unified data model. Migration primarily means:

- Adopt the unified request/response envelopes and binding semantics described in the Integration Guide.
- Use the consolidated back‑end configuration (trust anchors, identities, policies).
- Retain functionality via the integrated modules (_Warden makoto_ / _Warden roboto_); legacy artefacts exist under new names — see [Project Structure](structure.md).


!!! tip "TL;DR: What do I use now?"
    - **If you used WARDEN-roboto:** use **Warden roboto** (`at.asitplus.warden:roboto`) and the `Roboto` entry point.
    - **If you used WARDEN:** use **Warden makoto** (`at.asitplus.warden:makoto`) and the `Makoto` entry point.
    - **If you want the recommended end-to-end flow (client + verifier + unified wire format):** start with the [Integration Guide](supreme.md) (and its [data model](datamodel.md)).
    
    Cross-references:
    [Project Structure](structure.md) (where the modules live),
    [Usage without Integrated Clients](raw.md) (Makoto/Roboto directly),
    and [Externalising Configuration](config.md) (canonical config loading).

## Changes (Makoto + Roboto APIs)
This section focuses on upgrades that keep using `Makoto` / `Roboto` directly, without adopting the integrated model.

### Names, Entry Points, and Flow
- Legacy entry point types: `Warden` → `Makoto` and `AndroidAttestationChecker` → `Roboto`.
- Android verifier types renamed to `HardwareAttestationVerifier`, and `SoftwareAttestationVerifier`.
- Makoto can be configured for Android‑only or iOS‑only verification; attestations received from non‑configured platforms are treated as configuration errors. See [Error Handling](errorhandling.md).
- Attestation verification functions are suspending; blocking wrappers remain under legacy `@JvmName`s. See [raw flow](raw.md).
- The parameters `androidAttestationConfigurationJ` and `iosAttestationConfigurationJ` in `Makoto`'s Java-oriented constructor have been swapped to disambiguate it from the Kotlin constructors.

### Results and Exceptions
- `AttestationResult` gains a `Verified` marker; NOOP results are distinct.
- `AttestationResult.Error` always carries a `cause`.
- `AttestationValueException.Reason.TIME` is renamed to `STATEMENT_TIME`.
- Non-configured platforms return `AttestationResult.Error` with a configuration cause. See [Error Handling](errorhandling.md).

### Time Handling and Validity
- Verification time offset defaults to five minutes and is applied to certificate and attestation time checks.
- iOS attestation validity now uses the same `attestationStatementValiditySeconds` model as Android and rejects future‑dated statements.
- iOS verification time offset is no longer auto‑compensated, but the new defaults take this into account; increase `attestationStatementValiditySeconds` if you relied on the old behavior.
- Android leaf certificate validity is ignored by default; Android's `attestationStatementValiditySeconds` defaults to `null` (no statement time check). If configured, Android attestation creation time is verified.
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


Migrating code from WARDEN / WARDEN-roboto is rather smooth because the compiler and the IDE will scream at you
if you don't adapt to the changes.
Far more tricky is correct migration of externalised configuration.

Warden Supreme 1.0 introduces canonical serialised representations of Android- and iOS-specific attestation configurations.
Previously, Spring Boot and Hoplite could be used to load configurations directly.
However, the introduced flexibility of Warden Supreme with respect to Android revocation checks, in particular, means that
verifying and sanity-checking externalised configuration is only possible through code paths that are part of Warden
Supreme.
Hence, loading configurations must only be done through one of the following functions:

* `fromJsonString()`
* `fromYamlString()`
* `fromJsonObject()`

As a consequence, any Spring Boot configurations should contain a string pointing to Warden Supreme configurations, with
those configuration files being read and their contents being fed into `fromYamlString()`. For Hoplite you can do the same.



### Configuration Differences
Aside from changes to config loading, the actual configuration parameters and some defaults have changed between the last
stable WARDEN / WARDEN-roboto releases and Warden Supreme 1.0.0.

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
