# Migration from WARDEN / WARDEN‑roboto

Warden Supreme enforces unified flows and a unified data model. Migration primarily means:

- Adopt the unified request/response envelopes and binding semantics described in the Integration Guide.
- Use the consolidated back‑end configuration (trust anchors, identities, policies).
- Retain functionality via the integrated modules; legacy artifacts exist under new names — see [Project Structure](structure.md).

See also the authoritative configuration in [Integrating Warden Supreme](supreme.md#back-end-configuration), that hasn't changed.

!!! info "Need more migration depth?"
    If you require a step‑by‑step migration playbook or have edge cases not covered here, please [file an issue](https://github.com/a-sit-plus/warden-supreme/issues/new)
    or upvote an existing one in the tracker so we can prioritize expanding this guide.