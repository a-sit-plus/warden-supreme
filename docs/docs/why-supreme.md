# Why Warden Supreme?

If you only ever target one platform, you might be wondering:
why not use [`android/keyattestation`](https://github.com/android/keyattestation) or
[`veehaitch/devicecheck-appattest`](https://github.com/veehaitch/devicecheck-appattest) directly?

These libraries verify platform evidence. A deployable attestation service also needs to issue and consume challenges,
bind keys and application data to a ceremony, apply policy consistently, transport results, manage configuration, and
report failures safely. Warden Supreme provides this surrounding system, including the client-side implementation
required to participate in it.

## Quick Decision Guide

- Use **Warden Supreme** for a single verifier contract, shared policy semantics, and Android and iOS support without
  maintaining two separate integrations.
- Use **Warden makoto** if you need server-side verification only and custom/non-KMP clients.
- Use **Warden roboto** if you are truly Android-only and deliberately want minimal scope.
- Use platform-specific libraries directly if you explicitly want to own all protocol wiring, data model design, and long-term maintenance.

## What Warden Supreme Adds

!!! tip
    See the [full comparison matrix](#comparison-matrix) for a capability-by-capability comparison.

The platform libraries stop at verification primitives. Warden Supreme supplies the service and client integration
around them:

- Unified Back-end API and decision model shared across Android and iOS
- Unified Client API shared across Android and iOS
- Shared wire format and flow (`challenge` -> `attest` -> `certificate / error`)
- Challenge-selected signed proof of possession or hash-bound data authentication, including typed required/optional
  client-provided attributes
- Built-in iOS key-attestation emulation to mirror Android-style key-binding semantics
- One error and policy model instead of two independent verification stacks
- Defaults and maintained workarounds informed by years of operating attestation services in production
- Externalised configuration for attestation policy and verifier setup

## Operational Maturity

Warden Supreme's defaults and workarounds come from operating attestation services in production. Android and iOS do not
always conform to their own specifications, and the failures are often specific to a device, vendor, or OS release.
Warden Supreme accounts for known certificate-encoding defects, incorrect timestamps, broken validity periods, and other
platform behaviour encountered in real deployments without relaxing the security properties that remain enforceable.

These defaults were shaped by production deployments covering more than one million end-user devices across several
services. They provide a starting point that has already met the device diversity, timing problems, and implementation
defects that tend to appear only after an attestation service goes live.

## Configuration Externalisation

Warden Supreme supports external attestation configuration, allowing policy to be maintained independently of
application code and varied between deployments and environments.

The platform libraries intentionally hard-code little policy. When using them directly, you still need to define,
maintain, and evolve:

- a policy model structure,
- a mapping from external configuration to runtime verifier settings,
- validation and error handling for malformed or incomplete configuration, and
- framework-specific loader behaviour and environment-specific config quirks.

Warden Supreme includes this layer, together with Spring Boot and Hoplite configuration loading, so the same policy
model can be used across environments.
See [Externalising Configuration](integration/config.md).

## High-Assurance Android Policies

Warden Supreme also exposes Android verified-boot state as an explicit policy decision.

Android attestation does not force a choice between accepting only OEM firmware and admitting any modified device.
Warden Supreme supports three useful policies:

- Accept OEM-verified Android only
- Accept OEM Android and explicitly trusted hardened custom ROMs
- Accept only explicitly trusted hardened custom ROMs for high-security deployments

Locked-bootloader `SELF_SIGNED` verified boot keys are first-class policy inputs rather than automatic failures. A
custom-ROM deployment such as GrapheneOS can therefore be accepted without weakening integrity checks or falling back
to heuristics. This matters when:

- you want to admit users who rely on privacy- or hardening-focused Android distributions,
- you want to exclude generic OEM firmware in a high-security environment and admit only a curated hardened ROM fleet, or
- you need policy semantics that map directly to your threat model instead of being hardcoded in application logic.

See [Externalising Configuration](integration/config.md) for the actual policy format and
[Threat Models and Risks](bg/threatmodels.md) for when OEM-only, mixed, or custom-only policies make sense.

## Comparison Matrix

The table compares library scope rather than the quality of the underlying cryptographic verification. Warden Supreme
delegates platform-specific verification to these libraries and supplies the end-to-end system around it.

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

The architectural difference is scope. The upstream libraries determine whether a platform artefact is valid. Warden
Supreme also defines how this artefact is requested, transported, bound to a key and application data, evaluated across
platforms, turned into a certificate, configured in production, and reported when verification fails.

The above table is more than just a marketing skit.
The differences become material as soon as attestation has to operate as part of a service rather than as an isolated
certificate check. Using the platform libraries directly leaves the ceremony, data model, policy layer, configuration,
and operational handling to the integrating service.

We know this because Warden Supreme grew out of years spent designing, building, and operating attestation services. Its
predecessors eventually left us with three similar but incompatible implementations, each with its own rough edges, wire
format, and configuration model. Warden Supreme consolidates and evolves this experience into one reusable system
designed to serve different deployments and services, filling the gaps we encountered along the way.


## FAQ

### Is Warden Supreme "Wrapping Everything and Hiding Details"?

No. Warden Supreme standardises the integration layer while keeping platform-specific policy controls explicit. The
integrating service still decides what "trusted" means.

### Can I Use Only One Platform in Warden Supreme?

Yes. As of 1.0.0, verifier configuration can be Android-only or iOS-only by omitting the other platform's config.

### Do I Lose Flexibility if I Adopt Warden Supreme?

No. Custom clients and flows can use the verifier modules directly
(see [Usage without Integrated Clients](integration/raw.md)).

### Does This Only Work on Google Play Certified Android?

No. Warden Supreme can accept a locked-bootloader attestation rooted in an explicitly trusted verified boot key even
when the OS is not OEM-certified. This is how hardened custom ROMs such as GrapheneOS can be supported without weakening
the server-side integrity policy.

## Related Reading

- [End-to-End Integration](integration/supreme.md)
- [Usage without Integrated Clients](integration/raw.md)
- [Android Deep Dive](technical/android.md)
- [iOS Deep Dive](technical/ios.md)
- [References](refs.md)
