# Externalising Configuration


!!! tip "Configuration Reference"
    For the full configuration reference, see [Attestation Policy Configuration](supreme.md#attestation-policy-configuration).

!!! tip inline end "Configuration from Java"
    `SupremeConfiguration` accepts `java.time.Clock` and `java.time.Duration`, and its fixed clock accepts a
    `java.time.Instant`. See [Using Warden Supreme from Java](java.md#configuration-and-time).

Warden Supreme configuration consists of two parts:

1. Attestation policy configuration as explained in [Attestation Policy Configuration](supreme.md#attestation-policy-configuration), split into
    * `AndroidAttestationConfiguration` for Android specifics
    * `IosAttestationConfiguration` for iOS specifics
2. Configuration related to fully integrated attestation, such as OIDs used inside attestation proofs (CSRs) and key constraints, as explained in [Attestation Verifier Setup](supreme.md#attestation-verifier-setup).

## Unified, Canonical Configuration Formats

All externalised configuration classes implement `AttestationConfiguration`, providing one serialisation and loading
path across Android, iOS, and integrated setups.

!!! tip "Configuration Property Semantics"
    Canonical camel-case property names mirror the Kotlin properties. Their semantics are explained by the
    [annotated configuration example](supreme.md#config-options-example); the generated YAML and JSON examples below
    show the corresponding externalised structure and defaults.


!!! note "Changed Fingerprint Format"
    Android signer fingerprints were previously Base64-URL encoded. This is still supported, but the preferred representation is hex-encoded (with or without whitespace and/or `:` separators).  
    **Starting with release 1.1, only hex-encoded fingerprints will be supported.**

!!! note inline end "Changed YAML Format"
    Until 1.0.0-RC3, YAML polymorphic configs used a `type`/`value` wrapper. Newer versions use the same flat `type` shape as JSON. Legacy YAML with a `type`/`value` wrapper
    still works for `fromYaml`-based loading, **but will be retired with release 1.1**.

!!! warning "Quote YAML scalars that look numeric"
    This applies to all YAML loading paths: native `fromYaml...` readers, Hoplite, and Spring-backed YAML config.

    Some plain YAML scalars that look numeric or scientific can be parsed as numbers before Warden Supreme sees them.
    If a property is semantically a string, quote it.

    A concrete example is iOS build numbers such as `"21E236"`, which must stay quoted in YAML.

Each configuration type exposes:

* **Serialisation (instance methods):**
    * `toJsonString()`, `toYamlString()`
    * `toJsonElement()`
* **Deserialisation (companion object as `Reader`):**
    * `fromJsonString()`, `fromYamlString()`
    * `fromJsonObject()`
* **JVM file helpers (extension functions):**
    * `toJsonFile(...)` / `toYamlFile(...)`
    * `fromJsonFile(...)` / `fromYamlFile(...)`


External configuration must use these paths. Direct Spring Boot binding has
[problems with nullable properties](https://docs.spring.io/spring-boot/reference/features/external-config.html#features.external-config.application-json),
while reflection-based approaches that bypass primary constructors can also bypass validation.

??? tip "Loading with Hoplite (JVM)"
    Add the `at.asitplus.warden:config-hoplite` dependency to access `hopliteDecoder()`. Registering this decoder lets
    Hoplite load any `AttestationConfiguration` from its supported sources.
    The `hopliteDecoder()` function ensures that all config loading happens through well-defined serialisation paths.
    Loading like this accepts canonical camelCase, snake_case, UPPER_SNAKE_CASE, and kebap-case property names.
    
    ```kotlin
    --8<-- "Readme-Config-Hoplite.kt:hoplite-config-loader"
    ```
    
    **The decoder is required because Warden Supreme relies on kotlinx.serialization to sanitise, normalise, and parse
    configuration properties. Bypassing it also bypasses these code paths.**

??? tip "Spring Boot Loading (JVM)"
    Spring Boot loading is available through the `at.asitplus.warden:config-spring` module. It binds a
    Spring `Environment` (or a property prefix inside it) into a nested map and then calls `fromJsonObject()` so all
    validation and defaulting still go through the canonical configuration path.
    Loading like this accepts canonical camelCase, snake_case, UPPER_SNAKE_CASE, and kebap-case property names.

    !!! warning "Spring loading cannot reliably distinguish `null` from unset properties"
        This affects `fromSpringEnvironment(...)` and, in practice, also `fromSpringMap(...)` when that map originates
        from Spring's own config binding.

        Do **not** rely on Spring-backed loading to override a non-null default with an explicit `null`. Spring often
        normalises this value to an absent property before Warden Supreme receives it.

        If you need precise `null` semantics, load canonical configuration directly via
        `fromYamlString(...)`, `fromJsonString(...)`, `fromYamlFile(...)`, or `fromJsonFile(...)`.
        If you want Spring integration, use `fromSpringEnvironment(...)` on a prefix inside the Spring
        `Environment`, but treat explicit `null` overrides as unsupported.
    
    The module pulls Spring boot as a `compileOnly` dependency to avoid version conflicts. You bring your own Spring Boot
    dependency (3.x or 4.x) in the application.

    Supported and tested Spring loading scenarios include:

    * loading from a nested prefix inside a larger `Environment`
    * indexed collection binding from flat property maps
    * profile overrides and property-source precedence
    * composition through `spring.config.import`

    See [Quirks, Bugs, Workarounds, and Hints](../technical/quirks.md#configuration-loading) for Spring-specific caveats such as
    limitations around raw environment-variable binding.

    Example configuration:

    ```yaml
    --8<-- "Config-Spring-Boot-App.kt:springboot-config-yaml"
    ```
     
    Loading from a then environment using a prefix:
     
    ```kotlin
    --8<-- "Config-Spring-Boot-App.kt:springboot-env"
    ```
      
    Loading Android and iOS configuration through composition as part of configuration properties:
    
    ```kotlin
    --8<-- "Config-Spring-Boot-App.kt:springboot-config"
    ```

    Equivalent Java calls using `JavaSpringConfigurationLoader`:

    ```java
    --8<-- "at/asitplus/attestation/JavaSpringInteropAssertions.java:java-spring-env"
    ```

    ```java
    --8<-- "at/asitplus/attestation/JavaSpringInteropAssertions.java:java-spring-map"
    ```
    
    Both variants are intended for configuration embedded in a larger Spring Boot setup.
    **These loaders are required because Warden Supreme relies on kotlinx.serialization to sanitise, normalise, and parse
    configuration properties.**

## Supreme (Fully Integrated) Configuration
Use the umbrella `SupremeConfiguration` to externalise a fully integrated attestation flow.
It includes both the platform-specific configurations and the properties related to fully integrated attestation itself.

Two integrated-flow properties control proof authentication and client-provided attested values:

* `dataAuthentication` defaults to signature mode. Use `{ "type": "SIGNATURE" }` for a signed CSR with proof of
  possession, or `{ "type": "HASH", "algorithm": "SHA256" }` for an unsigned TBS CSR whose canonical hash input is
  bound through the platform attestation nonce.
* `toBeAttestedAttributes` is optional. It defines the dedicated CSR attribute OID and an ordered list of values. `type`
  uses readable `PrimitiveType` names (`STRING`, `INT`, `BOOLEAN`, `BYTEARRAY`, etc.); `required` defaults to `true`.

The generated YAML and JSON examples below demonstrate hash authentication together with one required and one optional
attestable attribute. Their example OID is the freely assignable UUID-based OID for
`e4da8413-46ae-4f0f-88f5-c7325b5850b0`. Generate a fresh UUID-derived `2.25` OID for your own attribute instead of
borrowing an enterprise subtree you do not control.

These are verifier defaults copied into each issued `AttestationChallenge`; `issueChallenge` can override them per
ceremony. `AttestationVerifier.decodeAttestationProof(…)` distinguishes a complete CSR from an unsigned TBS CSR structurally. The
matched challenge—not the HTTP layer or client transport—selects the expected mode and hash algorithm.

!!! danger "Bound Payload Sizes"
    `maxAttestationPayloadBytes` defaults to 1 MiB and limits raw attestation proofs when using
    `AttestationVerifier.decodeAttestationProof(…)`. Configure the same limit for the client and enforce it before an
     HTTP handler buffers or decodes a request body.  
     **Never use `Pkcs10CertificationRequest.decodeFromDer(…)` as advertised before Warden Supreme 1.0.3!** 

<div id="config-serialized"></div>

Both `AndroidAttestationConfiguration` and `IosAttestationConfiguration` are useful on their own if you don't opt for
fully integrated attestation, which is why they also have canonical serialised representations (JSON and YAML) and
expose the same (de)serialisation functions as `SupremeConfiguration`.

??? example "YAML with Defaults for a Sample Android and iOS App"
    The below example shows every configuration property in YAML form.
    It uses a single Android app and a single iOS app. Android revocation checks use the default Google revocation list,
    as well as a custom file-based revocation list. It also configures hash authentication and required and optional
    attestable attributes. All other properties show their default values.
    You can download the below example [here](../examples/supreme.yaml).
    
    ```yaml
    --8<-- "supreme.yaml"
    ```

??? example "JSON with Defaults for a Sample Android and iOS App"
    The below example shows every configuration property in JSON form.
    It uses a single Android app and a single iOS app. Android revocation checks use the default Google revocation list,
    as well as a custom file-based revocation list. It also configures hash authentication and required and optional
    attestable attributes. All other properties show their default values.
    You can download the below example [here](../examples/supreme.json).
    
    ```json
    --8<-- "supreme.json"
    ```

!!! tip "Fixed verification time"
    The examples use `clock: system`, which is the production default. For deterministic tests and replay, configure
    the built-in fixed time source:

    ```yaml
    clock:
      type: fixed # (1)
      instant: 2025-01-10T12:34:56.789Z # (2)
    ```

    1. `fixed` selects the serialisable `SupremeConfiguration.Clock.Fixed` implementation.
    2. `instant` pins verification to one ISO-8601 instant. This representation round-trips through YAML and JSON.

It is also possible to add other time sources and externalise their configurations by implementing
`SupremeConfiguration.Clock` and registering the classes for serialisation using `SupremeConfiguration.Clock.registry`.

!!! tip "Loading from a file"
    For JVM use-cases you can load directly from disk:
    
    * `SupremeConfiguration.fromYamlFile("supreme.yaml")`
    * `AndroidAttestationConfiguration.fromJsonFile("android.json")`
    
    and also write canonical configurations:
    
    * `cfg.toYamlFile("supreme.yaml")`
    * `cfg.toJsonFile("supreme.json")`


## Android Configuration

??? example "YAML for a Sample App"
    The below example shows every configuration property in YAML form.
    Applications aside, all properties show their default values, which means that a minimum configuration needs to contain only app information.
    As for deviations with respect to `revocation`:
    
    * An HTTP proxy is configured for the default HTTP-based revocation checker using the official Google revocation list.
    * A file-based revocation list is configured to allow for manually revoking certificates.
    
    You can download the below example [here](../examples/android.yaml).
    
    ```yaml
    --8<-- "android.yaml"
    ```

!!! tip "Known-good custom ROM keys"
    `verifiedBootKeys` defaults to `[OEM]`, which accepts vendor-managed `VERIFIED` boot on locked devices.
    Add pinned hex digests to also allow explicitly whitelisted `SELF_SIGNED` verified boot keys, or omit `OEM` to
    require only those custom keys. This only has an effect while `allowBootloaderUnlock` remains `false`, because
    Warden skips verified boot state and key checks entirely once unlocked bootloaders are allowed. A concrete example
    is GrapheneOS, which publishes its
    [verified boot key hashes](https://grapheneos.org/install/web#verified-boot-key-hash).

??? example "JSON for a Sample App"
    The below example shows every configuration property in JSON form.
    Applications aside, all properties show their default values, which means that a minimum configuration needs to contain only app information.
    As for deviations with respect to `revocation`:
    
    * An HTTP proxy is configured for the default HTTP-based revocation checker using the official Google revocation list.
    * A file-based revocation list is configured to allow for manually revoking certificates.
    
    You can download the below example [here](../examples/android.json).
    
    ```json
    --8<-- "android.json"
    ```

The HTTP loader used to fetch Google-official revocation lists can also be used generically for any HTTP-based
revocation checks. The only difference is in the configuration, as shown in the example below.

??? example "Custom HTTP Revocation List Loader Configuration"
    
    ```yaml
    - type: http
      url: 'https://superstrict.revocation.example.org/json'
      fallbackRevocationListValiditySeconds: 60
      preferHeaderBasedExpiry: false
      proxyConfig: 
        type: HTTP
        url: 'https://localhost:2345'
    ```

It is possible to create entirely new loaders and even externalise their configuration by implementing an
`AndroidRevocationList.Loader`  for the actual loader itself and an `AndroidRevocationList.Loader.Configuration`
for the externalisable configuration. The latter must be marked as `@Serializable` and registered using the
`AndroidRevocationList.loaderRegistry` **before the first configuration reading or writing happens**.

### Disabling Revocation Checks

Revocation checking is turned off by setting `revocation` to `DISABLED` (matched case-insensitively):

```yaml
revocation: DISABLED
```

No loader then runs at all, so no revocation list is fetched, consulted, or recorded in debug statements.

!!! warning "`revocation: []` is not accepted"
    An empty list looks like the obvious spelling, but Spring Boot cannot represent one: its YAML processor
    flattens both `[]` and `{}` into an *empty string*, which is indistinguishable from an unresolved shell
    variable, a blank Helm value, or an emptied CI secret. Reading a blank back as "no revocation checking"
    would let a typo silently switch a security control off, so blanks are rejected with an error naming the
    token, and `DISABLED` is the only accepted spelling in every format.

Because `DISABLED` is a plain scalar, it survives every Spring Boot property source unchanged:

```properties
attestation.android.revocation=DISABLED
```

```shell
--attestation.android.revocation=DISABLED
ATTESTATION_ANDROID_REVOCATION=DISABLED
```

It is also what `toYamlString()` and `toJsonString()` emit for an empty `revocation` list, so canonical
configuration written by Warden Supreme stays loadable by every format, Spring included.

!!! note "An empty in-memory revocation list cannot be configured from Spring Boot"
    A `mem` loader whose list has no entries (`list: { entries: {} }`) is a valid configuration in YAML and
    JSON, but not reachable from Spring Boot: an empty nested map contributes no properties at all, so both
    `entries` and its parent `list` disappear before any binder sees them. Use `revocation: DISABLED` if the
    intent is to skip revocation checking.


## iOS Configuration


??? example "YAML with Defaults for a Sample App"
    The below example shows every configuration property in YAML form.
    Applications aside, all properties show their default values, which means that a minimum configuration needs to contain only app information.  
    You can download the below example [here](../examples/ios.yaml).
    
    ```yaml
    --8<-- "ios.yaml"
    ```


??? example "JSON with Defaults for a Sample App"
    The below example shows every configuration property in JSON form.
    Applications aside, all properties show their default values, which means that a minimum configuration needs to contain only app information.  
    You can download the below example [here](../examples/ios.json).
    
    ```json
    --8<-- "ios.json"
    ```
