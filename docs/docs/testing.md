# Testing Strategy


!!! tip "New in Warden Supreme 1.2.0"
    Warden Supreme 1.2.0 adds the attestation generator, replacing the hand-rolled chain builders that integrators
    used to write. It is the same code Warden Supreme's own test suite verifies against, published as
    `at.asitplus.warden:generator`.  
    See [Attestation Generator](generator.md) for details.


A good attestation test strategy exercises the full pipeline without weakening production policy.
Three things make that work: strict separation of trust, realistic artefacts for automation, and staged environments that mirror production behaviour.
This splits into two layers: automated tests that run offline in CI against test identities, and end-to-end tests on
real devices across staging environments.

## Principles

- **Separate Trust Anchors** — Use distinct roots for test identities so production policies stay strict and verifiable. Never reuse production roots or signer digests in tests.
- **Record and Replay** — Capture real attestation inputs and verification outcomes (e.g., with Warden Supreme’s `WardenDebugAttestationStatement` as explained in [Debugging](integration/debugging.md)) and replay them offline for regression suites. This yields deterministic tests across CI and local runs.
- **Provisioning Realities** — On Android, Remote Key Provisioning can exhaust offline key pools during load; pre‑connect devices and warm pools before tests. Prefer emulators running Android 12 or below, and use a separate trust anchor for automation.
- **Stage Fidelity on iOS** — App Attest has sandbox and production environments with different AAGUIDs, producing attestation statements with properties set accordingly. Keep configurations consistent with the active stage to avoid cross‑stage contamination.

## Test Clients and Staging Pattern

Load tests and monitors must exercise attestation end to end without weakening production policy. Use a test app whose
cryptographic identity is distinct from the production app and admit it under a dedicated trust anchor.

- Configure a second app entry (e.g., `AndroidAttestationConfiguration.AppData`) with:
    - A different `packageName`
    - A deliberately obvious, non‑production signing certificate digest
    - An `androidVersionOverride` that is clearly out of band (e.g., very high) for easy detection
- Set up a test PKI:
    - A root whose public key is registered as a `trustAnchorOverride`
    - An intermediate that issues short‑lived leaves (the attestation certificate chain used by Android is always at least three certificates long, and its exact shape must match the claimed security level &mdash; see the warning under [Automated Attestation Tests](#attestation-security-level))
    - A leaf certificate generated on the fly by the test client so validity is always fresh
- Admit exactly two identities at the service:
    - The production app under the normal policy and roots
    - The test app under the test root and explicit allowlist
- Protect the test root private key rigorously; never issue test binding certificates that could be confused with production artefacts or grant production access.

This preserves production policy while enabling full-fidelity tests of binding, boot-state enforcement, and application
identity. Android-only fleet testing is often sufficient because iOS hardware behaves consistently.

## Staging Environments

Most deployments run one or two non-production stages before production. This section uses **T** (test), **Q**
(staging), and **P** (production).

- **P** admits only real production apps under production trust anchors. Nothing else validates there except for monitoring and the occasional load tests (see above).
- **T** and **Q** additionally configure faux apps (see [Test Clients and Staging Pattern](#test-clients-and-staging-pattern)), each with its own custom trust anchors and signer digests.
- **T** and **Q** mirror whatever proxy configuration is needed to reach external resources such as revocation lists.
- **T** and **Q** may point at custom, hardcoded revocation list sources so automated tests can control revocation state (see [Flexible Android Revocation Configuration](integration/supreme.md#flexible-android-revocation-configuration)).

Since the custom trust anchors live only on T and Q, any attestation proof minted against them is rejected on P by construction.

## Automated Attestation Tests

In addition to replaying recorded inputs, T and Q should test every proof property enforced by policy. Test code mutates
these properties, signs the resulting evidence, and wraps it in a valid chain rooted at the test trust anchor. Since P
does not trust this root, generated proofs cannot validate there.

This is the [Test Clients and Staging Pattern](#test-clients-and-staging-pattern) applied exhaustively: one generated proof per property (or combination) you care about, valid and invalid variants alike.

!!! tip "Generating Attestation Statements"
    Generated attestations are what makes the exhaustive part practical: one statement per property (or combination)
    worth enforcing, valid and invalid alike, all anchored in the test root so none of them can validate on production.
    Since Warden Supreme 1.2.0 they no longer have to be hand-rolled &mdash; the
    [Attestation Generator](generator.md) mints statements and matching certificate chains from Kotlin or from the
    command line, factory-provisioned and remotely provisioned chains included.

<span id="attestation-security-level"></span>
!!! warning "Generated chains must match the claimed security level"
    Starting with Warden Supreme 1.0.2, the verifier now **derives the attestation security level from the certificate chain when asserting `SecurityLevel.STRONGBOX`**  and requires it to match the level advertised in the attestation extension (`keymasterSecurityLevel`).
    Chain generators must therefore shape their output to match the claimed level:
    
    - **StrongBox** (factory-provisioned): `ROOT → FACTORY_INTERMEDIATE → ATTESTATION → TARGET` (four certificates).
        - The factory intermediate's subject must carry a serialNumber (OID `2.5.4.5`) **and** a title (OID `2.5.4.12`) of exactly or `StrongBox`.
        - The same is true for `TEE` Security level, but this is not hard-asserted, since the root will already indicate a proper hardware-backed attestation.
        - RKP chains are asserted just as strictly. Since Warden Supreme 1.2.0 they can be generated too &mdash; see the [Attestation Generator](generator.md).
    - **Software-backed**: `ROOT → ATTESTATION → TARGET` (three certificates), with no such title on the intermediate.
        - This is not enforced by the verifier.

## Tagging Apps via Custom Configuration Properties

Warden Supreme lets you attach `customProperties` &mdash; string key/value maps &mdash; to an app's attestation configuration (see [Attaching Custom Configuration Properties](integration/supreme.md#attaching-custom-configuration-properties)).
This makes the attestation configuration a source of application classification for downstream logic. An app tagged
`test-only`, for example, can receive more verbose logging or feed performance monitors without involving production
user data. These tags should not alter the core trust decision.

## End-to-End Tests on Real Devices

End-to-end testing starts after the unit and integration suites pass. Warden Supreme already tests captured evidence from
real devices alongside generated cases. Service integrators should then deploy release-candidate builds to physical
phones that can reach the staged service.

!!! tip "Attestation Collector"
    The [Attestation Collector](collector.md) is also useful for quickly exploring what an individual Android device
    produces. It is a public diagnostic service, not a replacement for testing your own app, signing identity, backend,
    and production policy.

Early testing benefits from the broadest available device pool: team devices, partner devices, and the devices already
used for compatibility testing. Most failures should match documented [quirks](technical/quirks.md), but the fleet may
still challenge assumptions about the target audience. In particular, expect more devices with discontinued security
updates than initial estimates suggest.

Once the service has reached its target audience, the attestation path usually stabilises. Policy changes can then be
checked against recorded evidence and a small representative in-house fleet before staged rollout.

### Rolling Out an App Update

One practical rollout pattern is a release build with a hidden switch that points the app at Q.
Typically, such a switch swaps endpoint URLs, trust anchors, and the like, but it should never change the app's behaviour.
It also makes sense that Q is configured to accept additional signing keys that P does not.
This way, a local release build is accepted on Q even though it was never distributed through official channels.
With this setup, the rollout is:

1. Deploy a release build to physical devices.
2. Flip the hidden switch to Q.
3. Run end-to-end tests with test credentials.
4. If everything checks out, distribute the updated app through official channels.

### Rolling Out a Service Update

Simpler, because nothing has to be rebuilt:

1. Deploy the updated service to Q.
2. Point current production apps at Q by using the hidden switch.
3. Run end-to-end tests.
4. Stage the updated service on P, ready to go.
5. Roll the update out on P if everything checked out on Q.

## Sharing Recorded Failures

Downstream integrators made many of Warden Supreme's production workarounds possible by sharing batches of recorded,
failed attestation attempts.

!!! Tip inline end "Sharing Recorded Failures"
    We offer downstream integrators to share collected failures with us: Send `serializeCompact()`-ed debug statements (see [Debugging](integration/debugging.md)) to [support.attestation@a-sit.at](mailto:support.attestation@a-sit.at),
    and we will use them to analyse potential device quirks.
    Use the compact format, never the human-readable one.
    **However, we will not accept any logs that contain IP addresses or any other data that could be used to correlate them with real user data, EVER!**

Attestation attempts collected downstream and shared with us are failures causing a hard termination of enrolment processes, which means that the users of these devices never gained access.
**Hence, no user data is generated for those attempts in the first place, so no personally identifiable data can be associated with those attestation attempts.**
We also never accepted any logs that contained IP addresses or any other data that could be used to correlate them with real user data.
We keep the collected failures private for a simple reason: The configuration needed to replay and analyse the failures includes the downstream integrator's package identifier and signer fingerprints.
So while there is no user data involved in failed attempts, the whole downstream configuration is included verbatim. Otherwise, we could not analyse the failures meaningfully.
For this reason, we run these collected failures in a private CI pipeline, locally, where there is no risk of exposing them.


!!! tip
    See the dedicated [Debugging](integration/debugging.md) page for practical details on diagnosing attestation errors.
