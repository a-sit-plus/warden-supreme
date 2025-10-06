# Testing Strategy

A sound attestation test strategy exercises the full pipeline without weakening production policy. Core ideas: strict separation of trust, realistic artifacts for automation, and staged environments that mirror production behavior.

## Principles

- **Separate Trust Anchors** — Use distinct roots for test identities so production policies stay strict and verifiable. Never reuse production roots or signer digests in tests.
- **Record and Replay** — Capture real attestation inputs and verification outcomes (e.g., with Warden Supreme’s `WardenDebugAttestationStatement` as explained in [Debugging](integration/debugging.md)) and replay them offline for regression suites. This yields deterministic tests across CI and local runs.
- **Provisioning Realities** — On Android, Remote Key Provisioning can exhaust offline key pools during load; pre‑connect devices and warm pools before tests. Prefer emulators running Android 12 or below, and use a separate trust anchor for automation.
- **Stage Fidelity on iOS** — App Attest has sandbox and production environments with different AAGUIDs, producing attestation statements with properties set accordingly. Keep configurations consistent with the active stage to avoid cross‑stage contamination.

## Test Clients and Staging Pattern

Goal: Enable load tests and monitors that fully exercise attestation without diluting production guarantees.

Approach: Introduce a test app identity that is cryptographically distinct from the production app and admitted under its own trust anchor.

- Configure a second app entry (e.g., `AndroidAttestationConfiguration.AppData`) with:
    - A different `packageName`
    - A deliberately obvious, non‑production signing certificate digest
    - An `androidVersionOverride` that is clearly out of band (e.g., very high) for easy detection
- Stand up a test PKI:
    - A root whose public key is registered as a `trustAnchorOverride`
    - An intermediate that issues short‑lived leaves (because the attestation certificate chain used by Android is always at least three certificates long)
    - A leaf certificate generated on the fly by the test client so validity is always fresh
- Admit exactly two identities at the service:
    - The production app under the normal policy and roots
    - The test app under the test root and explicit allowlist
- Protect the test root private key rigorously; never issue test binding certificates that could be confused with production artifacts or grant production access.

This preserves strict production posture while enabling full‑fidelity testing, including binding, boot state enforcement, and app identity checks. Often Android‑only testing suffices because iOS devices behave consistently.

## Debugging, Replay, and Diagnostics

!!! tip inline end
    See the dedicated [Debugging](integration/debugging.md) page for practical details on diagnosing attestation errors.

- Use Warden Supreme’s `collectDebugInfo(...)` on attestation errors to capture inputs, parsed fields, decisions, and failure reasons.
- Persist artifacts via `serialize()` / `serializeCompact()` to logs.
- Aggregate captures for offline analyses using smart replay to reproduce failures outside production.  
  Ideal for triaging field issues, validating fixes, and building CI regression suites.
- Enrich logs with device make/model, OS and patch levels, and boot state so OEM‑specific quirks can be correlated over time.

This approach yields predictable, auditable tests; clear stage boundaries; and realistic coverage of attestation flows across development, T/Q, and production.
