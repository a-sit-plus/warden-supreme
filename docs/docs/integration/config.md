# Externalising Configuration
Warden Supreme configuration consists of two parts:

1. Attestation policy configuration as explained in [Attestation Policy Configuration](supreme.md#attestation-policy-configuration), split into
   * `AndroidAttestationConfiguration` for Android specifics
   * `IosAttestationConfiguration` for iOS specifics
2. Configuration related to fully integrated attestation, such as OIDs used inside attestation proofs (CSRs) and key constraints, as explained in [Attestation Verifier Setup](supreme.md#attestation-verifier-setup).


To externalise such configuration in a convenient way, there is an umbrella `SupremeConfiguration`.
This configuration class includes both the platform-specific configurations and the configuration properties related
to fully integrated attestation.  
`SupremeConfiguration` has canonical serialised representations (JSON and YAML) and comes with the following (de)serialisation functions:

* `toJsonString()` and `fromJsonString()`
* `toYamlString()` and `fromYamlString()`
* `toJsonObject()` and `fromJsonObject()`

This is required for externalising configurations, as using Spring Boot's internal config loader to construct configurations is discouraged
due to [issues with handling nullable properties](https://docs.spring.io/spring-boot/reference/features/external-config.html#features.external-config.application-json).


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

Both `AndroidAttestationConfiguration` and `IosAttestationConfiguration` are useful on their own if you don't opt for fully integrated attestation, which is why they also
have canonical serialised representations (JSON and YAML) and expose the same (de)serialisation functions as `SupremeConfiguration`.
All three and their companion objects implement the same interface tandem to keep the API consistent.


## Android Configuration Files

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
      value: 
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


## iOS Configuration Files


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
