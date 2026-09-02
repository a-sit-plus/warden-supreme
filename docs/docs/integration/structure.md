# Project Structure

The repository contains five module groups:

1. `/supreme` contains the _Supreme_ integrated key and app attestation suite, building upon group&nbsp;2.
2. `/serverside` contains the server-side foundations with all the low-level logic to verify attestations.
3. `/utils` contains the [Attestation Generator](../generator.md) and unpublished helpers aimed at aiding analysis of attestation errors. The latter are meant to be used inside an IDE with an attached debugger.
4. `/dependencies` contains external dependencies that are not published to Maven Central or anywhere else and are thus compiled into group&nbsp;2 or used for testing.
5. `/collector` contains the source code for the [Attestation Collector](../collector.md).

!!! tip "Quick navigation"
    - For the recommended end-to-end flow (mobile client + verifier + unified wire format), start at the [Integration Guide](supreme.md).
    - For using the server-side libraries directly (without integrated clients), see [Usage without Integrated Clients](raw.md).
    - For WARDEN / WARDEN-roboto migration notes, see [Migration](migration.md).

## /supreme

| Name                                                                                                                          | Info                                                                                                                                              |
|-------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| <picture>  <img alt="Supreme verifier" src="../../assets/images/verifier-w.png" width="283"  style="height:auto;"> </picture> | Supreme verifier to be integrated into back-end services that want to remotely establish trust in mobile clients through key and app attestation. |
| <picture>  <img alt="Supreme client" src="../../assets/images/client-w.png" width="254" style="height:auto;"> </picture>      | Supreme client to be integrated into mobile apps that need to prove their integrity and trustworthiness to back-end services.                     |
| <picture>  <img alt="Supreme common" src="../../assets/images/common-w.png" width="262" style="height:auto;"> </picture>      | Commons containing shared client and verifier logic, data classes, etc.                                                                           |

### /supreme/config-hoplite

Lightweight JVM helper module that adds Hoplite decoders for `AttestationConfiguration` and routes loading through the canonical configuration readers.
See also [Externalising Configuration](config.md).

**Maven:** `at.asitplus.warden:config-hoplite`

### /supreme/config-spring

Lightweight JVM helper module that binds Spring Boot configuration into a map and feeds it through the canonical
`fromJsonObject()` path.
See also [Externalising Configuration](config.md).

**Maven:** `at.asitplus.warden:config-spring`

## /serverside

These modules can be used without the integrated Supreme attestation suite.

If you come from the legacy projects:
**WARDEN → _Warden makoto_** (`at.asitplus.warden:makoto`, entry point `Makoto`) and
**WARDEN-roboto → _Warden roboto_** (`at.asitplus.warden:roboto`, entry point `Roboto`).

| <img alt="Warden roboto" src="../../assets/images/roboto.png" width="249" style="height:auto;">                                                  | <picture>  <img alt="Warden makoto" src="../../assets/images/makoto-w.png" width="232" height="36" style="height:auto;"> </picture>                                                                                                                                                                                              | 
|--------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Android-only server-side key and app attestation library developed by A-SIT Plus. Used to be a separate project, now integrated here as a module. | Unified server-side Android and iOS key and app attestation library providing a common API to remotely establish trust in Android and iOS devices. Depends on Warden roboto and [Vincent Haupert's](https://github.com/veehaitch) excellent [DeviceCheck/AppAttest](https://github.com/veehaitch/devicecheck-appattest) library. |
| **Location:** `/serverside/roboto`                                                                                                                   | **Location:** `/serverside/makoto`                                                                                                                                                                                                                                                                                               |
| **Maven:** `at.asitplus.warden:roboto`                                                                                                    | **Maven:** `at.asitplus.warden:makoto`                                                                                                                                                                                                                                                                                           |

## /utils

This group contains the diagnostic utilities described in [Debugging](debugging.md), which are not published, and the
attestation generator, which is.

### /utils/generator

Creates Android key attestation statements and the certificate chains carrying them &mdash; factory-provisioned and
remotely provisioned &mdash; for automated tests and for reproducing device quirks. Statements are built on the same
types the verifier parses, so structurally invalid ones are expressible too.
See [Attestation Generator](../generator.md), which also links the stand-alone command-line tool.

**Maven:** `at.asitplus.warden:generator`

## /dependencies
Google released reference Android attestation parsers and PKIX certificate-path validators, but not complete verifiers
for remotely establishing trust in Android devices. These artefacts are unavailable from Maven Central, so Warden
Supreme includes them as Git submodules and compiles them into _Warden roboto_.

The group also contains an HTTP proxy used for testing. It is not included in release artefacts.

## /collector

This group contains the source code for the [Attestation Collector](../collector.md): a quick-and-dirty Compose
Multiplatform (CMP) app and its Ktor-based back-end. The collector makes it easy to produce and inspect an Android
attestation without first integrating Warden Supreme into another app and back end.

The collector is currently Android-only because iOS apps cannot be deployed outside Apple's App Store. iOS app
sources exist in the repository, but the collector's business logic is currently implemented only for Android.
