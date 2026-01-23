# Migration from WARDEN / WARDEN‑roboto

!!! danger "Warden Supreme Changed Defaults"
    Warden Supreme introduces behavioural changes compared to WARDEN / WARDEN-roboto:

    * Loading configurations through Hoplite and Spring Boot is no longer supported and can silently misconfigure checks; use canonical config loading instead. [Externalise](config.md) configs into a discrete file and load them explicitly.
    * Android leaf certificate validity is ignored by default; enable leaf validity enforcement if you depend on it. See [Externalised Configuration](config.md).
    * Android attestation statement validity defaults to `null`; ensure freshness via your challenge/nonce handling. See [raw flow](raw.md).
    * Verification time offset now defaults to five minutes and affects attestation time checks on both platforms.

    **Ignoring these changes can cause verification to accept stale attestations if you do not ensure freshness with nonces and checks.**

Warden Supreme enforces unified flows and a unified data model. Migration primarily means:

- Adopt the unified request/response envelopes and binding semantics described in the Integration Guide.
- Use the consolidated back‑end configuration (trust anchors, identities, policies).
- Retain functionality via the integrated modules; legacy artefacts exist under new names — see [Project Structure](structure.md).

## API Changes (Makoto + Roboto)
The following changes affect upgrades that keep using the Makoto/Roboto libraries without adopting the integrated model.

- **Renames:** `Warden` → `Makoto` and `AndroidAttestationChecker` → `Roboto` (deprecated typealiases remain for now). Android verifier types renamed to `HardwareAttestationVerifier`, `NougatHybridAttestationVerifier`, `SoftwareAttestationVerifier`.
- **Makoto construction:** Makoto can now be configured for Android‑only or iOS‑only verification; attestations for non‑configured platforms are treated as content errors. See [Error Handling](errorhandling.md).
- **Attestation challenge:** `includeGenericDeviceName` is replaced by `genericDeviceNameOID`; old constructors removed; challenge version bumped to `2`. See [attestation schema](../schemas/AttestationChallenge.json) and [data model](datamodel.md).
- **Challenge validity:** challenge validity is configured as a duration only; instant-based validity inputs were removed.
- **Results and exceptions:** `AttestationResult` gains a `Verified` marker; NOOP results are distinct; `AttestationResult.Error` always carries a `cause`; `AttestationValueException.Reason.TIME` is renamed to `STATEMENT_TIME`; `AttestationResult.Error.CONTENT` is returned for non-configured platforms. See [Error Handling](errorhandling.md).
- **Async verification:** Attestation verification functions are suspending; blocking wrappers remain under the legacy `@JvmName`s. See [raw flow](raw.md).
- **Configuration APIs:** New `AndroidAttestationConfiguration` and `IosAttestationConfiguration` with JSON/YAML (de)serialization; trust anchors now use `TrustedRoot`/`TrustedRootPair`. See [Externalised Configuration](config.md) and [Project Structure](structure.md).

## Behaviour Changes (Makoto + Roboto)
- **Time handling:** Verification time offset defaults to five minutes and is applied to certificate and attestation time checks; iOS attestation validity now uses the same `attestationStatementValiditySeconds` model as Android and rejects future‑dated statements; iOS verification time offset is no longer auto‑compensated, so increase `attestationStatementValiditySeconds` if you relied on the old behavior.
- **Android defaults:** Android leaf certificate validity is ignored by default; `attestationStatementValiditySeconds` defaults to `null` (no statement time check); if configured, Android attestation creation time is verified; patch level checks now reject patch levels too far in the future (default leeway: one month).
- **Revocation and trust anchors:** Revocation checks are configurable and chainable (HTTP/file/in‑memory loaders) and return richer details; revocation errors are classified under certificate trust errors rather than content errors and include the revocation list entry; per‑app trust anchor overrides change the order of checks so app metadata is validated before certificate chain validation. See [Android technical notes](../technical/android.md).
- **Remote Key Provisioning:** RKP checks are supported and can be required; failure yields a dedicated value error. See [Android technical notes](../technical/android.md).

See also the [data model](datamodel.md), [Error Handling](errorhandling.md), and the authoritative configuration example in the [Warden Supreme integration guide](supreme.md#config-options-example).


## Externalised Configuration

!!! tip inline end "List of Configuration Properties"
    See [Externalised Configuration](config.md) for an up-to-date list of all configuration properties.


Migrating code from WARDEN / WARDEN-roboto is rather smooth because the compiler and the IDE will scream at you
if you don't adapt to the changes.
Far more tricky is correct migration of externalised configuration.

Warden Supreme 1.0 introduces canonical serialised representations of Android- and iOS-specific attestation configurations.
Previously, Spring Boot and Hoplite could be used to load configurations directly.
However, the introduced flexibility of Warden Supreme wrt. Android revocation checks, in particular, means that
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
stable WARDEN / WARDEN-roboto releases and Warden Supreme 1.0.0

- **Android schema:** Trust anchors are now `TrustedRoot`s (`hardwareTrustedRoots` / `softwareTrustedRoots`); per‑app trust anchor overrides moved to `AppData.trustedRootOverrides`; `signatureDigests` is now `signerFingerprints`; `attestationStatementValiditySeconds` uses `Long` and can be `null`. See [Externalised Configuration](config.md) and [Android technical notes](../technical/android.md).
- **iOS schema:** iOS versions now require both SemVer and build number (`OsVersions`); per‑app trust anchor overrides use `TrustedRootPair`. See [Externalised Configuration](config.md) and [iOS technical notes](../technical/ios.md).



!!! info "Need more migration depth?"
    If you require a step‑by‑step migration playbook or have edge cases not covered here, please [file an issue](https://github.com/a-sit-plus/warden-supreme/issues/new)
    or upvote an existing one in the tracker so we can prioritise expanding this guide.
