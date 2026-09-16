# Using Warden Supreme from Java

Warden Supreme is written in Kotlin, but its server-side JVM modules can also be used from Java. The regular data model
and configuration classes are directly accessible; small Java-facing adapters bridge the places where the Kotlin API
uses suspending functions, receiver lambdas, or Kotlin time types.

!!! info "Java-only API"
    Java-only adapters are deliberately marked `internal` in Kotlin source so they do not clutter the Kotlin API.
    Kotlin/JVM still emits them as public JVM declarations, and `@JvmName` gives their methods stable, idiomatic Java
    names. The examples on this page are compiled and exercised from the Java test source set.

## Integrated Attestation

For a new integration, use `JavaAttestationVerifier`. It wraps the Kotlin-first `AttestationVerifier` and exposes:

* regular methods instead of suspending functions
* an ordinary `Callbacks` interface instead of Kotlin receiver lambdas and `FunctionN` types
* `CompletableFuture` results for challenge issuance and attestation verification

The following complete example is compiled as part of the JVM test suite:

```java
--8<-- "SupremeVerifierJavaApi.java:java-example-verifier"
```

1. Configure the iOS application using the regular Java constructor.
2. Create the platform and integrated policy through the Java-friendly configuration helper shown below.
3. Implement the regular Java callback interface. The challenge has already been validated when this callback runs.
4. Successful verification provides both the verified platform result and the attested public key.
5. Return `null` to accept the proof after application-specific checks, or return an `AttestationResponse.Failure` to
   reject it.
6. Return the certificate chain issued for the attested key. An empty list is useful only when exercising an error path,
   as this test example does.
7. Keep one verifier instance and compose the returned futures at the application's asynchronous boundary.

!!! tip "Working with `CompletableFuture`"
    Use `thenApply`, `thenCompose`, or `exceptionally` to continue asynchronously. `join()` is convenient at a genuinely
    synchronous boundary, but must not block an event-loop thread.

## Configuration and Time

`SupremeConfiguration` provides a Java-friendly constructor with nullable iOS and Android policies followed by Java
standard-library time types:

```java
--8<-- "SupremeVerifierJavaApi.java:java-example-configuration"
```

1. Pass the iOS policy, or `null` for an Android-only verifier.
2. Pass the Android policy, or `null` for an iOS-only verifier. At least one platform policy must be present.
3. Supply the clock used for verification. `Clock.systemUTC()` is the default.
4. Set the verification-time offset used to compensate for clock drift. The default is five minutes.

The constructor uses `@JvmOverloads`, so trailing arguments can be omitted when their defaults are suitable. In
particular, `new SupremeConfiguration(iosConfiguration, androidConfiguration)` uses the system UTC clock and the default
verification-time offset.

For deterministic tests, construct a serialisable fixed clock with
`new SupremeConfiguration.Clock.Fixed(java.time.Instant)`. An existing Java clock can also be adapted with
`SupremeConfiguration.Clock.from(java.time.Clock)`.

!!! note "Clocks in externalised configuration"
    `Clock.Fixed` and the system clock have canonical YAML and JSON representations. A clock created with `Clock.from(...)`
    is a runtime adapter and should not be written to externalised configuration. See
    [Externalising Configuration](config.md) for the supported formats.

## Using Makoto or Roboto Directly

The integrated flow above is the recommended path. The APIs in this section are useful when the application owns its
wire format and calls [_Warden makoto_ or _Warden roboto_ directly](raw.md).

### _Warden makoto_

`Makoto` provides Java constructors for combined, Android-only, and iOS-only policies:

* `Makoto(IosAttestationConfiguration, AndroidAttestationConfiguration, java.time.Duration, java.time.Clock)`
* `Makoto(AndroidAttestationConfiguration, java.time.Duration, java.time.Clock)`
* `Makoto(IosAttestationConfiguration, java.time.Duration, java.time.Clock)`

All three use `@JvmOverloads`; the trailing duration and clock can therefore be omitted. The combined constructor
requires both policies, while the platform-specific constructors configure only their named platform.

The most useful synchronous Java methods are:

* `verifyKeyAttestation(Attestation, byte[])` for the unified key-attestation representation
* `getAndroid().verifyKeyAttestationBlocking(List<X509Certificate>, byte[])` for a raw Android certificate chain
* `getIos().verifyAppAttestation(byte[], byte[])` for an App Attest object and challenge
* `getIos().verifyCombined(byte[], byte[], byte[], byte[])` for App Attest plus assertion verification
* the `collectDebugInfo(...)` overload matching the failed verification call

The first method is named `verifyKeyAttestationBlocking` in Kotlin source, but Java sees
`verifyKeyAttestation(...)` through `@JvmName`. Overloads accepting the legacy `List<byte[]>` proof format are deprecated
and should only be used while migrating an existing integration.

### _Warden roboto_

Construct `Roboto` with an `AndroidAttestationConfiguration`. A second constructor accepting a Kotlin `Function2` is
visible on the JVM, but the one-argument overload provides the intended Java experience and compares challenge bytes by
content.

Java can then call:

* `verifyBlocking(List<X509Certificate>, java.time.Instant, byte[])`, or omit the instant to use the current time
* `collectDebugInfo(List<X509Certificate>, byte[], java.time.Instant)`
* `collectDebugInfo(List<X509Certificate>, byte[], java.util.Date)`
* `collectDebugInfoBlocking(List<X509Certificate>, byte[], java.time.Instant)`, or omit the instant

The two `collectDebugInfo(...)` overloads are hidden from the public Kotlin API, while being exposed to Java.
The similarly named top-level Kotlin extension functions are emitted on
`RobotoKt`, use Kotlin time types, and are not intended as the Java entry point, but for calling from Kotlin.
