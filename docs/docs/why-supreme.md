# Why Warden Supreme?

If you only ever target one platform, you might be wondering:
why not use [`android/keyattestation`](https://github.com/android/keyattestation) or
[`veehaitch/devicecheck-appattest`](https://github.com/veehaitch/devicecheck-appattest) directly?

Short answer: Warden Supreme is not a replacement for those libraries.
It builds on top of them and provides a unified integration and policy layer around them.

## Quick Decision Guide

- Use **Warden Supreme** if you want a single verifier contract, shared policy semantics, and an easy path to Android+iOS without re-architecting later.
- Use **Warden makoto** if you need server-side verification only and custom/non-KMP clients.
- Use **Warden roboto** if you are truly Android-only and deliberately want minimal scope.
- Use platform-specific libraries directly if you explicitly want to own all protocol wiring, data model design, and long-term maintenance.

## What Warden Supreme Adds

The platform libraries deliberately stop at verification primitives. Warden Supreme adds the layer on top of them that
you would otherwise write yourself:

- Unified Back-end API and decision model shared across Android and iOS
- Unified Client API shared across Android and iOS
- Shared wire format and flow (`challenge` -> `attest` -> `certificate / error`)
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

While upstreamed to the platform libraries, also hardcode very little wrt. policy, using them directly would still have
you define, maintain, and evolve:

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

| Criterion                                       | Warden Supreme                                               | `android/keyattestation`                    | `veehaitch/devicecheck-appattest`                            |
|-------------------------------------------------|--------------------------------------------------------------|---------------------------------------------|--------------------------------------------------------------|
| Primary scope                                   | End-to-end Android+iOS attestation integration               | Android attestation verification primitives | iOS App Attest verification primitives                       |
| Platform coverage                               | Android + iOS                                                | Android only                                | iOS only                                                     |
| Unified server contract                         | Yes                                                          | No                                          | No                                                           |
| Unified mobile client contract                  | Yes (integrated clients)                                     | No                                          | No                                                           |
| Key-attestation semantics on iOS                | Built in (emulated key attestation)                          | Not applicable                              | Requires your own binding design around App Attest semantics |
| Policy model                                    | Shared high-level policy with platform-specific config knobs | Android-specific only                       | iOS-specific only                                            |
| Production-hardened defaults and quirk handling | Included and continuously maintained                         | You own this                                | You own this                                                 |
| Externalised configuration support              | Included                                                     | You design and maintain it                  | You design and maintain it                                   |
| Wire format and endpoint flow                   | Included and documented                                      | You design it                               | You design it                                                |
| Multi-platform future-proofing                  | High                                                         | Low                                         | Low                                                          |
| Integration effort                              | Lower for end-to-end flows                                   | Higher for full product integration         | Higher for full product integration                          |

## Android-Only: Why Not Just `android/keyattestation`?

If your service is Android-only and you want full custom control, using Android-specific tooling directly can be reasonable.
Yet Warden Supreme still pays off when you want:

- a ready-made, production-oriented verification flow instead of hand-rolled endpoint contracts,
- a cleaner migration to iOS later without replacing your verifier architecture, or
- shared policy and error handling across present and future platforms,
- attestation logic that accounts for platform quirks and evolves with Android releases.

## iOS-Only: Why Not Just DeviceCheck/App Attest Helpers?

If your service is iOS-only, and you want to own all server/client wiring, using App Attest helpers directly can be reasonable.

Warden Supreme still pays off when you want:

- iOS key-binding semantics aligned with Android via built-in key-attestation emulation,
- a consistent attestation lifecycle model without custom glue code, or
- easier future expansion to Android with minimal conceptual churn,
- attestation logic that accounts for platform quirks and evolves with iOS releases.

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
