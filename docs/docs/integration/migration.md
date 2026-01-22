# Migration from WARDEN / WARDEN‑roboto

!!! danger "Warden Supreme Changed Defaults"
    Warden Supreme introduces behavioural changes compared to WARDEN / WARDEN-roboto:

    * Loading configurations through Hoplite and Spring Boot is not supported any more and may lead to sublte, but critical 
      misconfigurations without raising any apparent errors during startup! [Externalise](config.md) Warden Supreme configs into a discrete file
      and reference it inside your Spring Boot or Hoplite Configuration.
    * Android leaf cert validity is ignored by default, because Warden Supreme (by default) uses random cryptographic nonces.
        * `ingoreLeafValidity()` (yes, with typo!) function of the `AndroidAttestationConfiguration.Builder` is now a deprecated NOOP to be removed.
        * `enforceLeafValidity()` (without typo!) function was introduced
    * Android `attestationStatementValiditySeconds` defaults to `null`, because Warden Supreme, by default, uses random cryptographic nonces.
    * Attestation verification time offset now defaults to five minutes to account for clock drift
    * iOS attestation validity is increased by said five minutes
    
    **Ignoring these changes can result in a total security failure if you do not ensure freshness through means of feeding
    random cryptographic nonces into attestation statement creation and properly checking them!**

Warden Supreme enforces unified flows and a unified data model. Migration primarily means:

- Adopt the unified request/response envelopes and binding semantics described in the Integration Guide.
- Use the consolidated back‑end configuration (trust anchors, identities, policies).
- Retain functionality via the integrated modules; legacy artifacts exist under new names — see [Project Structure](structure.md).

See also the [data model](datamodel.md) and the authoritative configuration example in the [Warden Supreme integration guide](supreme.md#config-options-example).


## Externalised Configuration

!!! tip inline end "List of Configuration Properties"
    See [Externalised Configuration](config.md) for an up-to-date list of all configuration properties.


Migrating code from WARDEN / WARDEN-roboto is rather smooth because the compiler and the IDE will scream at you
if you don't adapt to the changes.
Far more tricky is a correct migration externalised configuration.

Warden Supreme 1.0 introduces canonical serialised representations of Android- and iOS-specific attestation configurations.
Previously, Spring Boot and Hoplite could be used to load configurations directly.
However, the introduced flexibility of Warden Supreme wrt. Android revocation checks, in particular, means that
verifying and sanity-checking externalised configuration is only possible through code paths that are part of Warden
Supreme.
Hence, loading configurations must only be done through one of the following functions:

* `fromJsonString()`
* `fromYamlString()`
* `fromJsonObject()`

As a consequence, any Spring boot configurations should contain a string pointing to Warden Supreme configurations, with
those configuration files being read and their contents being fed into `fromYamlString()`. For Hoplite you can do the same.



### Configuration Differences
Aside from changes to config loading, the actual configuration parameters and some defaults have changed between the last
stable WARDEN / WARDEN-roboto releases and Warden Supreme 1.0.0


!!! info "Need more migration depth?"
    If you require a step‑by‑step migration playbook or have edge cases not covered here, please [file an issue](https://github.com/a-sit-plus/warden-supreme/issues/new)
    or upvote an existing one in the tracker so we can prioritize expanding this guide.