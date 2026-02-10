# Project Structure

Warden Supreme is structured into four groups:

1. `/supreme` contains the _Supreme_ integrated key and app attestation suite, building upon group&nbsp;2.
2. `/serverside` contains the server-side foundations with all the low-level logic to verify attestations.
3. `/utils` contains unpublished utility helpers aimed at aiding analysis of attestation errors. These are meant to be used inside an IDE with an attached debugger.
4. `/dependencies` contains external dependencies that are not published to Maven Central or anywhere else and are thus compiled into group&nbsp;2 or used for testing.

!!! tip "Quick navigation"
    - For the recommended end-to-end flow (mobile client + verifier + unified wire format), start at the [Integration Guide](supreme.md).
    - For using the server-side libraries directly (without integrated clients), see [Usage without Integrated Clients](raw.md).
    - For WARDEN / WARDEN-roboto migration notes, see [Migration](migration.md).

## /supreme

| Name                                                                                                                                                                                                                                                                                                                    | Info                                                                                                                                      |
|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| <picture>  <source media="(prefers-color-scheme: dark)" srcset="../../assets/images/verifier-w.png">  <source media="(prefers-color-scheme: light)" srcset="../../assets/images/verifier-b.png">  <img alt="Supreme verifier" src="../../assets/images/verifier-b.png" width="283"  style="height:auto;"> </picture> | Supreme verifier to be integrated into back-end services that want to remotely establish trust in mobile clients through key and app attestation. |
| <picture>  <source media="(prefers-color-scheme: dark)" srcset="../../assets/images/client-w.png">  <source media="(prefers-color-scheme: light)" srcset="../../assets/images/client-b.png">  <img alt="Supreme client" src="../../assets/images/client-b.png" width="254" style="height:auto;"> </picture>     | Supreme client to be integrated into mobile apps that need to prove their integrity and trustworthiness to back-end services.                |
| <picture>  <source media="(prefers-color-scheme: dark)" srcset="../../assets/images/common-w.png">  <source media="(prefers-color-scheme: light)" srcset="../../assets/images/common-b.png">  <img alt="Supreme common" src="../../assets/images/common-b.png" width="262" style="height:auto;"> </picture>         | Commons containing shared client and verifier logic, data classes, etc.                                                                     |

### /supreme/config-hoplite

Lightweight JVM helper module that adds Hoplite decoders for `AttestationConfiguration`.
See also [Externalising Configuration](config.md).

**Maven:** `at.asitplus.warden:config-hoplite`

### /supreme/config-spring

**Experimental** lightweight JVM helper module that binds Spring Boot configuration into a map and feeds it through the canonical
`fromJsonObject()` path.
See also [Externalising Configuration](config.md).

**Maven:** `at.asitplus.warden:config-spring`

## /serverside

The modules located here can be used on their own, in case the Supreme integrated attestation suite is not desired.

If you come from the legacy projects:
**WARDEN → _Warden makoto_** (`at.asitplus.warden:makoto`, entry point `Makoto`) and
**WARDEN-roboto → _Warden roboto_** (`at.asitplus.warden:roboto`, entry point `Roboto`).

| <img alt="Warden roboto" src="../../assets/images/roboto.png" width="249" style="height:auto;">                                                  | <picture>  <source media="(prefers-color-scheme: dark)" srcset="../../assets/images/makoto-w.png">  <source media="(prefers-color-scheme: light)" srcset="../../assets/images/makoto-b.png">  <img alt="Warden makoto" src="../../assets/images/makoto-w.png" width="232" height="36" style="height:auto;"> </picture>      | 
|--------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Android-only server-side key and app attestation library developed by A-SIT Plus. Used to be a separate project, now integrated here as a module. | Unified server-side Android and iOS key and app attestation library providing a common API to remotely establish trust in Android and iOS devices. Depends on Warden roboto and [Vincent Haupert's](https://github.com/veehaitch) excellent [DeviceCheck/AppAttest](https://github.com/veehaitch/devicecheck-appattest) library. |
| **Location:** `/serverside/roboto`                                                                                                                   | **Location:** `/serverside/makoto`                                                                                                                                                                                                                                                                                                  |
| **Maven:** `at.asitplus.warden:roboto`                                                                                                    | **Maven:** `at.asitplus.warden:makoto`                                                                                                                                                                                                                                                                                   |

## /utils
This group houses the debugging/examination utils described in [Debugging](debugging.md).

## /dependencies
Google released reference Android attestation parsers (not full attestation checkers for remotely establishing trust in Android devices) and PKIX certificate path validators to complement parsing.
They did not, however, publish those artefacts to Maven Central. Warden Supreme therefore integrates them as Git submodules and compiles them into _Warden roboto_.

In addition, an HTTP proxy is present to facilitate testing. It is not, however, shipped with any artefacts.
