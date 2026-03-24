# Why Warden Supreme?

If you only target one platform, this is the right question to ask:
why not use [`android/keyattestation`](https://github.com/android/keyattestation) or [`veehaitch/devicecheck-appattest`](https://github.com/veehaitch/devicecheck-appattest) directly?

Short answer: Warden Supreme is not a replacement for those libraries.
It builds on top of them and provides a unified integration and policy layer around them.

## Quick Decision Guide

- Use **Warden Supreme** if you want a single verifier contract, shared policy semantics, and an easy path to Android+iOS without re-architecting later.
- Use **Warden makoto** if you need server-side verification only and custom/non-KMP clients.
- Use **Warden roboto** if you are truly Android-only and deliberately want minimal scope.
- Use platform-specific libraries directly if you explicitly want to own all protocol wiring, data model design, and long-term maintenance.

## What Warden Supreme Adds

Warden Supreme provides a product-level integration layer that platform-specific attestation libraries intentionally do not provide:

- Unified back-end API and decision model across Android and iOS
- Unified client API across Android and iOS (for integrated clients)
- Shared wire format and flow (`challenge` -> `attest` -> `certificate / error`)
- Built-in iOS key-attestation emulation to mirror Android-style key-binding semantics
- Consistent error and policy handling instead of two independent verification stacks
- Sane defaults and maintained workarounds for platform quirks informed by years of production operation
- Externalised configuration support for attestation policy and verifier setup

## Operational Maturity (The Hard-Won Part)

Warden Supreme ships with defaults and guardrails shaped by long-running production usage and real device diversity.
Its behaviour reflects years of learnings and continuously maintained workarounds for platform quirks.

In practice, this means:

- You start from production-oriented defaults rather than designing every knob from scratch
- Known Android/iOS edge cases are already accounted for and revisited as platform behaviour evolves
- You reduce the risk of repeating well-known integration and validation pitfalls that teams often rediscover when rolling their own

This operational maturity is based on large real-world production cohorts (over one million end-user devices across services), not only lab or emulator scenarios.

## Configuration Externalisation

Warden Supreme already supports externalising attestation configuration and wiring.
That means policy can be managed outside code where needed (deployment/environment specific), instead of hardcoding all verifier settings.

With platform libraries alone, teams still need to design and maintain:

- A policy model structure
- A mapping from external config -> runtime verifier settings
- Validation/error handling for malformed or incomplete config
- Framework-specific loader behaviour and environment-specific config quirks

Warden Supreme reduces this integration overhead and makes policy operations more predictable.
See [Externalising Configuration](integration/config.md).

## High-Assurance Android Policies

One place where Warden Supreme goes beyond "just wire the platform library" is Android verified-boot policy.

Modern Android attestation does not force you into a false choice between "accept only OEM Android" and
"allow any unlocked or modified device". Warden Supreme lets you express the policy you actually want:

- Accept OEM-verified Android only
- Accept OEM Android and explicitly trusted hardened custom ROMs
- Accept only explicitly trusted hardened custom ROMs for high-security deployments

This works by treating locked-bootloader `SELF_SIGNED` verified boot keys as first-class policy inputs rather than as
an automatic failure case. In practice, that means secure custom-ROM deployments such as GrapheneOS can be supported
without weakening integrity checks or falling back to heuristics.

In practice, this matters for any of the following cases:

- You want to embrace users that depend on privacy- or hardening-focused Android distributions
- You want to exclude generic OEM firmware in a high-security environment and admit only a curated hardened ROM fleet
- You need policy semantics that map directly to your threat model instead of being hardcoded in application logic

See [Externalising Configuration](integration/config.md) for the actual policy format and
[Threat Models and Risks](bg/threatmodels.md) for when OEM-only, mixed, or custom-only policies make sense.

## Comparison Matrix

| Criterion | Warden Supreme | `android/keyattestation` | `veehaitch/devicecheck-appattest` |
|---|---|---|---|
| Primary scope | End-to-end Android+iOS attestation integration | Android attestation verification primitives | iOS App Attest verification primitives |
| Platform coverage | Android + iOS | Android only | iOS only |
| Unified server contract | Yes | No | No |
| Unified mobile client contract | Yes (integrated clients) | No | No |
| Key-attestation semantics on iOS | Built in (emulated key attestation) | Not applicable | Requires your own binding design around App Attest semantics |
| Policy model | Shared high-level policy with platform-specific config knobs | Android-specific only | iOS-specific only |
| Production-hardened defaults and quirk handling | Included and continuously maintained | You own this | You own this |
| Externalised configuration support | Included | You design and maintain it | You design and maintain it |
| Wire format and endpoint flow | Included and documented | You design it | You design it |
| Multi-platform future-proofing | High | Low | Low |
| Integration effort | Lower for end-to-end flows | Higher for full product integration | Higher for full product integration |

## Android-Only: Why Not Just `android/keyattestation`?

If your service is permanently Android-only and you want full custom control, using Android-specific tooling directly can be reasonable.

Warden Supreme (or `makoto` / `roboto`) is still useful when you want:

- A ready-made, production-oriented verification flow instead of hand-rolled endpoint contracts
- Cleaner migration to iOS later without replacing your verifier architecture
- Shared policy and error handling style across present and future platforms

## iOS-Only: Why Not Just DeviceCheck/App Attest Helpers?

If your service is permanently iOS-only and you want to own all server/client wiring, using App Attest helpers directly can be reasonable.

Warden Supreme (or `makoto`) is still useful when you want:

- iOS key-binding semantics aligned with Android via built-in key-attestation emulation
- A consistent attestation lifecycle model without custom glue code
- Easier future expansion to Android with minimal conceptual churn

## FAQ

### Is Warden Supreme "wrapping everything and hiding details"?

No. Warden Supreme standardises the integration layer while keeping platform-specific policy controls explicit.
You still decide what "trusted" means.

### Can I use only one platform in Warden Supreme?

Yes. As of 1.0.0, verifier configuration can be Android-only or iOS-only by omitting the other platform config.

### Do I lose flexibility if I adopt Warden Supreme?

No. If you need custom clients or custom flows, use the verifier modules directly
(see [Usage without Integrated Clients](integration/raw.md)).

### Does this only work on Google Play certified Android?

No. If the device presents a locked-bootloader attestation with a verified boot key you trust, Warden Supreme can
accept it even when the OS is not OEM-certified. That is exactly how you can support hardened custom ROMs such as
GrapheneOS without weakening your server-side integrity policy.

## Related Reading

- [End-to-End Integration](integration/supreme.md)
- [Usage without Integrated Clients](integration/raw.md)
- [Android Deep Dive](technical/android.md)
- [iOS Deep Dive](technical/ios.md)
- [References](refs.md)
