# Attestation Generator

Warden Supreme does not only verify Android key attestations, it can also produce them. The generator mints attestation
statements and the certificate chains that carry them &mdash; from Kotlin, or from the command line &mdash; for
[automated attestation tests](testing.md#automated-attestation-tests), for reproducing a device quirk, or simply to see
what a statement looks like before writing any verification code.

It works on the same types the verifier parses (`AttestationKeyDescription` and `AuthorizationList`), so anything Warden
Supreme can read, the generator can write &mdash; including statements no real device would ever produce.

!!! abstract "Command-line tool"
    The generator runs stand-alone, so test fixtures can be produced without writing any Kotlin. It takes one
    [JSON configuration](#command-line-use) and writes a certificate chain and an attested private key per statement,
    plus the root certificate:

    ```bash
    java -jar attestation-generator.jar config.json
    ```

    [:material-download: attestation-generator.jar](downloads/attestation-generator.jar){ .md-button }

To build statements from Kotlin instead, add the generator as a test dependency:

```kotlin
testImplementation("at.asitplus.warden:generator:$version")
```

## Issuing an Attestation

An issuer holds the root and the attestation CA chain. Every `issue` call mints a fresh attestation key and a fresh
attested leaf key, exactly as a device does:

```kotlin
--8<-- "GeneratorExamples.kt:generator-issue"
```

1. The chain shape follows the provisioning method: `factoryProvisioned()` puts one factory CA under the root,
   `rkp()` puts `Droid CA2` and `Droid CA3` there. This is what a verifier reads the security level off, so it is not
   cosmetic &mdash; see the warning under [Automated Attestation Tests](testing.md#attestation-security-level).
2. The attestation challenge. Everything else defaults to a plausible, empty KeyMint 4.0 statement.
3. Leaf first, root last: hand this to `verify()`, and register the root as a trust anchor.
4. The attested private key, for signing whatever the attestation vouches for (a CSR, for instance).

## A Complete Device Statement

Authorization lists are built with the parser's own constructor, so the schema is the only reference needed:

```kotlin
--8<-- "GeneratorExamples.kt:generator-statement"
```

1. Versions and security level of the statement itself. `securityLevel` sets both the attestation and the KeyMint level.
2. Software-enforced properties: creation time and the attested application's identity.
3. Hardware-enforced properties: key parameters and everything the TEE vouches for.
4. Boot state, boot key digest and lock state &mdash; the properties most policies actually enforce.

## Remote Key Provisioning

```kotlin
--8<-- "GeneratorExamples.kt:generator-rkp"
```

1. Remote key provisioning names its CAs the way Google's do, and states the security level as the attestation
   certificate's organisation (`O=TEE` or `O=StrongBox`).
2. Five certificates instead of four: `root → Droid CA2 → Droid CA3 → attestation → leaf`.

## One Trust Anchor, Many Attestations

A single issuer is a test PKI: keep it for the lifetime of the suite, register its root once, and issue as many
attestations under it as needed:

```kotlin
--8<-- "GeneratorExamples.kt:generator-anchor"
```

1. Reuse an existing root by assigning `root = RootSpec(certificatePem, privateKeyPkcs8Pem)` instead of letting the
   generator create one.
2. Issuance time and certificate lifetime are explicit, so tests can place a chain anywhere on the timeline.
3. Register this as the trust anchor of the test configuration (`TrustedRoot.PublicKey` or `TrustedRoot.Certificate`).

## Negative Test Vectors

Every property can also be replaced by raw ASN.1, which is how structurally invalid statements are built &mdash; the case
a lenient parser must survive and a strict policy must reject:

```kotlin
--8<-- "GeneratorExamples.kt:generator-mangled"
```

1. The complete, explicitly tagged property as DER: here `keySize [3]` carrying `INTEGER 128` where the schema wants a
   key size. Anything goes, including values that cannot be decoded at all.

## Command-Line Use

A configuration built with the DSL exports to exactly the JSON the [command-line tool](#attestation-generator) consumes,
so a fixture worked out in Kotlin can be handed to CI as a file:

```kotlin
--8<-- "GeneratorExamples.kt:generator-config"
```

1. `configuration()` returns the configuration that reproduces this issuer, ready to be written to a file.
2. Any number of statements, each issued into its own certificate chain.
3. A generated root is exported into the configuration, so re-running the CLI keeps the same trust anchor.

Configurations are plain JSON: authorization-list properties are the complete DER of each property, which is what makes
invalid values expressible. These four examples are generated and verified by Warden Supreme's own test suite on every
build:

??? example "Minimal: everything but the timestamps left at its default"
    ```json
    --8<-- "generator-minimal.json"
    ```

    You can download this example [here](examples/generator-minimal.json).

??? example "What a TEE-backed device attests to"
    A factory-provisioned TEE chain with an application identity, key parameters, root of trust, OS version and patch level.
    ```json
    --8<-- "generator-tee-factory.json"
    ```

    You can download this example [here](examples/generator-tee-factory.json).

??? example "StrongBox, provisioned remotely"
    The remotely provisioned chain shape, with a device-unique attestation and a module hash, valid for half an hour.
    ```json
    --8<-- "generator-strongbox-rkp.json"
    ```

    You can download this example [here](examples/generator-strongbox-rkp.json).

??? example "Two statements that must be rejected"
    A `keySize` replaced by valid-but-wrong ASN.1, and a device that failed verified boot while emitting a property
    outside the schema.
    ```json
    --8<-- "generator-negative-vectors.json"
    ```

    You can download this example [here](examples/generator-negative-vectors.json).

Run it against any of those, and it writes one certificate chain and one attested private key per statement, plus the
root certificate, into `outputDirectory`:

```bash
java -jar attestation-generator.jar generator-tee-factory.json
```

[:material-download: attestation-generator.jar](downloads/attestation-generator.jar){ .md-button }

!!! warning "Test material only"
    Everything the generator produces is anchored in a root it generates (or one supplied to it), never in a Google root.
    Chains minted this way validate only where their root is explicitly trusted &mdash; which is the point, and the reason
    test roots must never be configured on production.
