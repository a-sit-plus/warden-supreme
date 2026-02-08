# Externalising Configuration
Warden Supreme configuration consists of two parts:

1. Attestation policy configuration as explained in [Attestation Policy Configuration](supreme.md#attestation-policy-configuration), split into
    * `AndroidAttestationConfiguration` for Android specifics
    * `IosAttestationConfiguration` for iOS specifics
2. Configuration related to fully integrated attestation, such as OIDs used inside attestation proofs (CSRs) and key constraints, as explained in [Attestation Verifier Setup](supreme.md#attestation-verifier-setup).

## Unified, Canonical Configuration Formats

All externalised configuration classes implement `AttestationConfiguration`. This provides a
single, canonical way to serialise and load configurations across Android, iOS, and integrated setups.

!!! note inline end "Changed YAML Format"
    Until 1.0.0-RC3, YAML polymorphic configs used a `type`/`value` wrapper. Newer versions use the same flat `type` shape as JSON. Legacy YAML with a `type`/`value` wrapper
    still works for `fromYaml`-based loading, but will be retired with release 1.1.

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


These well-defined serialisation paths are required for externalising configurations, because external logic, such as Spring Boot's internal config loader,
tends to have [issues with handling nullable properties](https://docs.spring.io/spring-boot/reference/features/external-config.html#features.external-config.application-json).
In addition, approaches based on reflection that do not invoke the configuration classes' primary constructors may bypass sanity-checks.

??? tip "Loading with Hoplite (JVM)"
    Add the `at.asitplus.warden:config-hoplite` dependency to access `hopliteDecoder()`. This way you can directly load any `AttestationConfiguration` by
    registering the provided decoder and letting Hoplite load from your preferred sources (files, env, etc.).  
    The `hopliteDecoder()` function ensures that all config loading happens throuhg well-defined serialisation paths.
    
    ```kotlin
    --8<-- "Readme-Config-Hoplite.kt:15:25"
    ```

## Supreme (Fully Integrated) Configuration
To externalise configuration for fully integrated attestation flows conveniently, use the umbrella `SupremeConfiguration`.
It includes both the platform-specific configurations and the properties related to fully integrated attestation itself.

Both `AndroidAttestationConfiguration` and `IosAttestationConfiguration` are useful on their own if you don't opt for
fully integrated attestation, which is why they also have canonical serialised representations (JSON and YAML) and
expose the same (de)serialisation functions as `SupremeConfiguration`.

??? example "YAML with Defaults for a Sample Android and iOS App"
    The below example shows every configuration property in YAML form.
    It uses a single Android app and a single iOS app. Android revocation checks use the default Google revocation list,
    as well as a custom file-based revocation list. All other properties show their default values.  
    You can download the below example [here](../examples/supreme.yaml).
    
    ```yaml
    --8<-- "supreme.yaml"
    ```

??? example "JSON with Defaults for a Sample Android and iOS App"
    The below example shows every configuration property in JSON form.
    It uses a single Android app and a single iOS app. Android revocation checks use the default Google revocation list,
    as well as a custom file-based revocation list. All other properties show their default values.  
    You can download the below example [here](../examples/supreme.json).
    
    ```json
    --8<-- "supreme.json"
    ```

It is possible to add time sources other than the system clock and externalise their configurations as well by implementing
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
