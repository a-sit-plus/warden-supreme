# Why Warden Supreme?

If you only ever target one platform, you might be wondering:
why not use [`android/keyattestation`](https://github.com/android/keyattestation) or
[`veehaitch/devicecheck-appattest`](https://github.com/veehaitch/devicecheck-appattest) directly?

Those libraries are deliberately focused verification engines. Warden Supreme builds on them, but its scope is much
larger: it provides the client ceremony, wire protocol, challenge lifecycle, cross-platform policy, key binding, optional
proof of possession, application-data authentication, certificate issuance hooks, configuration, error semantics, and
operational safeguards needed to turn platform attestation primitives into a deployable system.

## Quick Decision Guide

- Use **Warden Supreme** if you want a single verifier contract, shared policy semantics, and an easy path to Android+iOS without re-architecting later.
- Use **Warden makoto** if you need server-side verification only and custom/non-KMP clients.
- Use **Warden roboto** if you are truly Android-only and deliberately want minimal scope.
- Use platform-specific libraries directly if you explicitly want to own all protocol wiring, data model design, and long-term maintenance.

## What Warden Supreme Adds

!!! tip
    See the [full comparison matrix](#comparison-matrix) to see how much added value Warden Supreme brings.

The platform libraries deliberately stop at verification primitives. Warden Supreme adds the layer on top of them that
you would otherwise write yourself:

- Unified Back-end API and decision model shared across Android and iOS
- Unified Client API shared across Android and iOS
- Shared wire format and flow (`challenge` -> `attest` -> `certificate / error`)
- Challenge-selected signed proof of possession or hash-bound data authentication, including typed required/optional
  client-provided attributes
- Built-in iOS key-attestation emulation to mirror Android-style key-binding semantics
- One error and policy model instead of two independent verification stacks
- Sane defaults and maintained workarounds for platform quirks, informed by years of production operation
- Externalised configuration for attestation policy and verifier setup

## Operational Maturity

The defaults and workarounds shipped with Warden Supreme come out of running attestation in production, not out of a
specification. Both Android and iOS don't always behave according to spec.
Warden Supreme has already encountered those edge cases &mdash; device models that report attestation slightly
differently, OS versions with known bugs, timing quirks &mdash; and it accounts for them, shipping pre-baked
workarounds that are known to work in production without degrading security.

The concrete payoff: you start from defaults that have survived real device diversity, and you avoid rediscovering the
integration and validation pitfalls that tend to surface only once a service is live. These defaults were shaped by
production cohorts of over one million end-user devices across several services, not just by lab or emulator runs.

## Configuration Externalisation

Warden Supreme already supports externalising attestation configuration and wiring.
Hence, policy can be managed outside independently of code and maintained deployment/environment specific.

The platform libraries intentionally hard-code little policy. When using them directly, you still need to define,
maintain, and evolve:

- a policy model structure,
- a mapping from external configuration to runtime verifier settings,
- validation and error handling for malformed or incomplete configuration, and
- framework-specific loader behaviour and environment-specific config quirks.

Warden Supreme ships this already, including direct integration with Spring Boot and Hoplite config loading,
so policy changes stay predictable across environments.
See [Externalising Configuration](integration/config.md).

## High-Assurance Android Policies

One place where Warden Supreme goes beyond "just wire the platform library" is Android verified-boot policy.

Modern Android attestation does not force a choice between "accept only OEM Android" and "allow any unlocked or
modified device". You can express the policy you actually want:

- Accept OEM-verified Android only
- Accept OEM Android and explicitly trusted hardened custom ROMs
- Accept only explicitly trusted hardened custom ROMs for high-security deployments

This works by treating locked-bootloader `SELF_SIGNED` verified boot keys as first-class policy inputs rather than as an
automatic failure case. Consequently, a secure custom-ROM deployment such as GrapheneOS can be accepted without weakening integrity
checks or falling back to heuristics.  
Concretely, this matters when:

- you want to admit users who rely on privacy- or hardening-focused Android distributions,
- you want to exclude generic OEM firmware in a high-security environment and admit only a curated hardened ROM fleet, or
- you need policy semantics that map directly to your threat model instead of being hardcoded in application logic.

See [Externalising Configuration](integration/config.md) for the actual policy format and
[Threat Models and Risks](bg/threatmodels.md) for when OEM-only, mixed, or custom-only policies make sense.

## Comparison Matrix

The below table compares library scope, not the quality of the underlying cryptographic verification. Warden Supreme delegates
the platform-specific work to these libraries and adds the end-to-end system around it.

| Capability                                        | `android/keyattestation`                                       | `devicecheck-appattest`                              | Warden Supreme                                                                        |
|---------------------------------------------------|----------------------------------------------------------------|------------------------------------------------------|---------------------------------------------------------------------------------------|
| Primary abstraction                               | Android certificate-chain verifier                             | Apple App Attest verifier                            | Complete mobile attestation and key-certification ceremony                            |
| Unified API for Android and iOS                   | ❌                                                             | ❌                                                   | Yes, with shared challenge, result, and policy concepts                               |
| Server-side verification                          | Android only                                                   | iOS only                                             | Android, iOS, or both from one verifier                                               |
| Integrated mobile client                          | ❌                                                             | ❌                                                   | Kotlin Multiplatform Android/iOS client                                               |
| Automated hardware-backed key creation            | ❌                                                             | ❌                                                   | Integrated with challenge-provided key requirements                                   |
| iOS key-attestation semantics                     | ❌                                                             | App Attest primitive; binding design is caller-owned | App Attest is composed into Android-like key-attestation semantics                    |
| Challenge creation                                | ❌                                                             | ❌                                                   | Issued by the verifier with nonce, validity, endpoint, policy, and app payload        |
| Challenge expiry and replay protection            | Challenge checkers and an optional in-memory LRU are available | ❌                                                   | Bounded cache, one-time consumption, expiry, and pluggable persistence contract       |
| Clock-drift handling                              | ❌                                                             | ❌                                                   | Integrated into challenge and attestation validity checks                             |
| Client/server wire protocol                       | ❌                                                             | ❌                                                   | Versioned challenge, DER proof transport, and structured response model               |
| Signed proof of possession                        | ❌                                                             | ❌                                                   | Built in through a signed PKCS#10 CSR                                                 |
| Authentication without signing                    | ❌                                                             | ❌                                                   | Hash-bound TBS CSR through the platform attestation nonce                             |
| Typed client-provided attested attributes         | ❌                                                             | ❌                                                   | Ordered required/optional attributes with ASN.1 type validation                       |
| Binding application data to attestation           | Raw challenge checker available                                | Assertion challenge validator available              | Integrated into signed or hash-authenticated CSR contents                             |
| Binding the claimed public key to the attestation | Exposes the attested public key                                | ❌                                                   | Mandatory verifier check in both authentication modes                                 |
| CSR construction and validation                   | ❌                                                             | ❌                                                   | Canonical TBS CSR/CSR construction, structural validation, and ambiguity checks       |
| Certificate issuance                              | ❌                                                             | ❌                                                   | Verified-result callback receives the authenticated request and issues a chain        |
| Stable cross-platform result model                | Android-specific results                                       | iOS-specific exceptions/results                      | Unified success plus `TRUST`, `TIME`, `CONTENT`, and `INTERNAL` failures              |
| Typed integration callbacks                       | Verification hooks                                             | Verification hooks                                   | Challenge, client-data, attestation, policy, success, and issuance callbacks          |
| Additional service policy checks                  | ❌                                                             | ❌                                                   | First-class pre-issuance verification callback with structured failures               |
| Android application identity policy               | Constraint primitives                                          | ❌                                                   | Package and signer policy in the unified configuration                                |
| iOS application identity policy                   | ❌                                                             | App identity validation                              | Team, bundle, environment, receipt, and assertion policy in the unified configuration |
| Android verified-boot policy                      | Parsed/constraint data available                               | ❌                                                   | OEM-only, mixed OEM/custom-ROM, or explicitly trusted custom-ROM policies             |
| Remote Key Provisioning policy                    | Provisioning information is exposed                            | ❌                                                   | Can require RKP globally or per application and select appropriate roots              |
| Android trust anchors                             | Google defaults or caller-provided anchors                     | ❌                                                   | Google, RKP, and custom roots with application-level policy                           |
| Android revocation                                | Google revocation source/checking                              | ❌                                                   | Google plus composable HTTP, file, and custom revocation sources                      |
| iOS assertions and counters                       | ❌                                                             | Assertion validation                                 | Exposed through Warden makoto with canonical persistence helpers                      |
| iOS receipts                                      | ❌                                                             | Validation and exchange primitives                   | Integrated into Warden makoto policy and verification                                 |
| External JSON/YAML configuration                  | ❌                                                             | ❌                                                   | Canonical serialisation for the complete verifier policy                              |
| Spring Boot configuration                         | ❌                                                             | ❌                                                   | Dedicated integration module                                                          |
| Hoplite configuration                             | ❌                                                             | ❌                                                   | Dedicated integration module                                                          |
| Multiple apps and environments                    | Caller orchestration                                           | Caller orchestration                                 | Multiple Android/iOS app policies in one configuration                                |
| Platform-quirk workarounds                        | Unsatisfactory in practice                                     | iOS verifier scope                                   | Cross-platform workarounds maintained from production device behaviour                |
| Debuggable attestation failures                   | ❌ (only Android-specific result details)                      | ❌ (only iOS-specific exceptions)                    | Unified typed callbacks plus serialisable debug statements for offline analysis       |
| End-to-end emulator coverage                      | ❌                                                             | ❌                                                   | Client-to-verifier Android emulator scenarios across auth and attribute combinations  |
| Escape hatch for custom flows                     | Direct verifier API                                            | Direct verifier API                                  | Integrated Supreme API or lower-level makoto/roboto APIs                              |

The difference is architectural: the upstream libraries answer “is this platform artefact valid?” Warden Supreme also
answers “how is it requested, transported, bound to a key and application data, evaluated consistently across platforms,
turned into a certificate, configured in production, and reported safely when anything fails?”

The above table is more than just a marketing skit.
It effectively means if you want to use vanilla DeviceCheck/App Attest or `android/keyattestation`, you'd end up implementing a good chunk of what Warden Supreme gives you from scratch.
It won't work as well, and you'll hit the same walls we did, while developing Warden Supreme, and you'll end up re-doing much of the work that went into Warden Supreme.  
How do we know? Warden Supreme is the culmination of doing precisely that multiple times.

In the end, we had three slightly different, slightly incompatible implementations with subtle rough edges in different places and incompatible wire formats and configuration
mechanisms&hairsp;&mdash;&hairsp;even when already using Warden Supreme's predecessors, WARDEN and WARDEN-roboto.


## FAQ

### Is Warden Supreme "wrapping everything and hiding details"?

No. Warden Supreme standardises the integration layer while keeping platform-specific policy controls explicit.
You still decide what "trusted" means.

### Can I use only one platform in Warden Supreme?

Yes. As of 1.0.0, verifier configuration can be Android-only or iOS-only by omitting the other platform's config.

### Do I lose flexibility if I adopt Warden Supreme?

No. If you need custom clients or custom flows, use the verifier modules directly
(see [Usage without Integrated Clients](integration/raw.md)).

### Does this only work on Google Play certified Android?

No. If the device presents a locked-bootloader attestation with a verified boot key you trust, Warden Supreme can
accept it even when the OS is not OEM-certified. That is exactly how you support hardened custom ROMs such as
GrapheneOS without weakening your server-side integrity policy.

## Related Reading

- [End-to-End Integration](integration/supreme.md)
- [Usage without Integrated Clients](integration/raw.md)
- [Android Deep Dive](technical/android.md)
- [iOS Deep Dive](technical/ios.md)
- [References](refs.md)
