# Testing Strategy

A good attestation test strategy exercises the full pipeline without weakening production policy.
Three things make that work: strict separation of trust, realistic artefacts for automation, and staged environments that mirror production behaviour.
In practice this splits into two layers &mdash; automated tests that run offline in CI against faux identities, and end-to-end tests on real devices across staging environments.

## Principles

- **Separate Trust Anchors** — Use distinct roots for test identities so production policies stay strict and verifiable. Never reuse production roots or signer digests in tests.
- **Record and Replay** — Capture real attestation inputs and verification outcomes (e.g., with Warden Supreme’s `WardenDebugAttestationStatement` as explained in [Debugging](integration/debugging.md)) and replay them offline for regression suites. This yields deterministic tests across CI and local runs.
- **Provisioning Realities** — On Android, Remote Key Provisioning can exhaust offline key pools during load; pre‑connect devices and warm pools before tests. Prefer emulators running Android 12 or below, and use a separate trust anchor for automation.
- **Stage Fidelity on iOS** — App Attest has sandbox and production environments with different AAGUIDs, producing attestation statements with properties set accordingly. Keep configurations consistent with the active stage to avoid cross‑stage contamination.

## Test Clients and Staging Pattern

Load tests and monitors need to exercise attestation end to end without diluting production guarantees.
This can be achieved with minimum effort by using a test app whose identity that is cryptographically distinct from the production app and admitted under its own trust anchor.
[testing.md](testing.md)
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

This preserves strict production posture while enabling full‑fidelity testing, including binding, boot state enforcement, and app identity checks. Often Android‑only testing suffices because iOS devices behave consistently.

## Staging Environments

Most deployments typically run one or two non‑production stages in front of production. For the sake of clarity, this section assumes the following stages: **T** (test), **Q** (staging), and **P** (production).

- **P** admits only real production apps under production trust anchors. Nothing else validates there except for monitoring and the occasional load tests (see above).
- **T** and **Q** additionally configure faux apps (see [Test Clients and Staging Pattern](#test-clients-and-staging-pattern)), each with its own custom trust anchors and signer digests.
- **T** and **Q** mirror whatever proxy configuration is needed to reach external resources such as revocation lists.
- **T** and **Q** may point at custom, hardcoded revocation list sources so automated tests can control revocation state (see [Flexible Android Revocation Configuration](integration/supreme.md#flexible-android-revocation-configuration)).

Since the custom trust anchors live only on T and Q, any attestation proof minted against them is rejected on P by construction.

## Automated Attestation Tests

On top of replaying recorded inputs, T and Q typically carry automated tests that cover every property in an attestation proof that the attestation policy actually checks.
Test code generates faux attestation chains on demand by mutating those properties, signs them properly, and wraps them in a valid certificate chain rooted at the test trust anchor.
Since the test trust anchor is trusted only on T and Q, these generated proofs never validate on P.

This is the [Test Clients and Staging Pattern](#test-clients-and-staging-pattern) applied exhaustively: one generated proof per property (or combination) you care about, valid and invalid variants alike.

<span id="attestation-security-level"></span>
!!! warning "Generated chains must match the claimed security level"
    Starting with Warden Supreme 1.0.2, the verifier now **derives the attestation security level from the certificate chain when asserting `SecurityLevel.STRONGBOX`**  and requires it to match the level advertised in the attestation extension (`keymasterSecurityLevel`).
    Chain generators must therefore shape their output to match the claimed level:
    
    - **StrongBox** (factory-provisioned): `ROOT → FACTORY_INTERMEDIATE → ATTESTATION → TARGET` (four certificates).
        - The factory intermediate's subject must carry a serialNumber (OID `2.5.4.5`) **and** a title (OID `2.5.4.12`) of exactly or `StrongBox`.
        - The same is true for `TEE` Security level, but this is not hard-asserted, since the root will already indicate a proper hardware-backed attestation.
        - RPK chains are also asserted as strictly, but cannot currently be generated, due to hard checks against the actual production certificate chain.
    - **Software-backed**: `ROOT → ATTESTATION → TARGET` (three certificates), with no such title on the intermediate.
        - This is not enforced by the verifier.

## Tagging Apps via Custom Configuration Properties

Warden Supreme lets you attach `customProperties` &mdash; string key/value maps &mdash; to an app's attestation configuration (see [Attaching Custom Configuration Properties](integration/supreme.md#attaching-custom-configuration-properties)).
This tiny configuration addon allows the attestation configuration to become your source of truth for how trustworthy a given app is, and expose this to your business logic by carrying a custom tag.
Tag an app `test-only`, for example, and downstream logic can treat it differently from a production app, or single out any other app that deserves special handling.
While this should not influence core business logic to remain accurate, it can be used to increase loggin verbosity, tap into perf monitors, or to do all sorts of other things you do not want to involve real user data in.

## End-to-End Tests on Real Devices

End-to-end tests typically start once the unit and integration suites are green.
Warden Supreme already contains a comprehensive test suite based on data captured from real devices and generated test data.
Once unit and integration tests on the service-level are green, the next step is to run end-to-end tests on real devices.
At this point it makes sense to deploy what are meant to be the final release builds on physical phones that can connect to a deployed service.

Early on, this means using the app on as many phones as possible. For example, handed the app to everyone on the team and pull in partner (and their real devices) as well to get a diverse device pool.
Unless you are operating in a region where Warden Supreme was never used before, expect to only come across already documented [quirks](technical/quirks.md) (which Warden Supreme handles out of the box).
However, testing with a wide array of devices may already reveal some misconceptions and false assumptions about your target audience.
Most prominently, expect to see more devices not receiving any software updates than you initially anticipated.

Once everything is up and running, and you have reached your target user base, the attestation path should be pretty much settled.
If everything is chugging along nicely in production, and you have all the insights about your target audience, testing changes to attestation policies can usually be done with just a handful of in-house devices.

### Rolling Out an App Update

One of the simplest ways to roll out an app update for release builds to ship with a hidden switch that flips the app to the Q stage.
Typically, such a switch swaps endpoint URLs, trust anchors, and the like, but it should never change the app's behaviour.
It also makes sense that Q is configured to accept additional signing keys that P does not.
This way, a local release build is accepted on Q even though it was never distributed through official channels.
With this setup, testing becomes straight-forward:

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

What ultimately let us work around essentially every known quirk from real-world devices was that some downstream integrators shared batches of recorded, failed attestation attempts with us.

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
