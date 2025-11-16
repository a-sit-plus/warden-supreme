# Migration from WARDEN / WARDEN‑roboto

!!! danger "Warden Supreme 0.9.99 Changed Defaults"
    
    * Android leaf cert validity is ignored by default, because Warden Supreme (by default) uses random cryptographic nonces.
        * `ingoreLeafValidity()` (yes, with typo!) function of the `AndroidAttestationConfiguration.Builder` is now a deprecated NOOP to be removed.
        * `enforceLeafValidity()` (without typo!) function was introduced
    * Android `attestationStatementValiditySeconds` defaults to `null`, because Warden Supreme, by default, uses random cryptographic nonces.
    * Attestation verification time offset now defaults to five minutes to account for clock drift
    * iOS attestation validity is increased by said five minutes
    
    **Ignoring these changes can result in a total security failure if you do not ensure freshness through means of feeding random cryptographic nonces into attestation statement creation and properly checking them!**

Warden Supreme enforces unified flows and a unified data model. Migration primarily means:

- Adopt the unified request/response envelopes and binding semantics described in the Integration Guide.
- Use the consolidated back‑end configuration (trust anchors, identities, policies).
- Retain functionality via the integrated modules; legacy artifacts exist under new names — see [Project Structure](structure.md).

See also the authoritative configuration example in the [Warden Supreme integration guide](supreme.md#config-options-example).

!!! info "Need more migration depth?"
    If you require a step‑by‑step migration playbook or have edge cases not covered here, please [file an issue](https://github.com/a-sit-plus/warden-supreme/issues/new)
    or upvote an existing one in the tracker so we can prioritize expanding this guide.