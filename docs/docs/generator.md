# Attestation Generator

Besides verifying Android key attestations, Warden Supreme can also produce them. The generator creates attestation
statements, the certificate chains carrying them, and the corresponding private keys. It is available as a Kotlin
library and as a command-line tool. Typical uses include [automated attestation tests](testing.md#automated-attestation-tests),
reproducing device quirks, and inspecting the format without first writing a verifier integration.

Statements are built from the same `AttestationKeyDescription` and `AuthorizationList` types consumed by the parser.
This also permits generating malformed or outright nonsensical input. Real devices have already demonstrated why that
is a useful feature.

!!! abstract "Command-Line Tool"
    Test fixtures do not require Kotlin code. The stand-alone generator takes one
    [JSON configuration](#command-line-use) and writes a certificate chain and attested private key for every statement,
    together with the root certificate:

    ```bash
    java -jar attestation-generator.jar config.json
    ```

    [:material-download: attestation-generator.jar](downloads/attestation-generator.jar){ .md-button }

To build statements from Kotlin instead, add the generator as a test dependency:

```kotlin
testImplementation("at.asitplus.warden:generator:$version")
```

## Issuing an Attestation

An issuer holds the root and the attestation CA chain. Every call to `issue` creates a fresh attestation key and a fresh
attested leaf key, mirroring the key hierarchy produced by a device:

```kotlin
--8<-- "GeneratorExamples.kt:generator-issue"
```

1. The provisioning method determines the chain shape. `factoryProvisioned()` places one factory CA below the root;
   `rkp()` uses `Droid CA2` and `Droid CA3`. The verifier derives the security level from this structure, so getting it
   wrong changes the meaning of the chain. See [Automated Attestation Tests](testing.md#attestation-security-level).
2. The attestation challenge. Unspecified fields retain the defaults of an otherwise empty KeyMint 4.0 statement.
3. Certificate chains are returned leaf first and root last. Pass the chain to `verify()` and configure its root as a
   trust anchor.
4. The attested private key is returned as well, ready to sign a CSR or another payload covered by the test.

## A Complete Device Statement

Use the parser's own `AuthorizationList` constructor to fill in a statement. It covers the entire schema and keeps the
generator from growing a second, inevitably slightly different model:

```kotlin
--8<-- "GeneratorExamples.kt:generator-statement"
```

1. `securityLevel` sets both the attestation and KeyMint security levels; either can still be overridden separately.
2. Creation time and application identity belong to the software-enforced list.
3. Key parameters and properties vouched for by the TEE belong to the hardware-enforced list.
4. The root of trust records verified boot state, the boot-key digest, and whether the bootloader is locked. These are
   usually the interesting bits when testing policy.

## Remote Key Provisioning

```kotlin
--8<-- "GeneratorExamples.kt:generator-rkp"
```

1. Remote key provisioning follows Google's CA names and records the security level in the attestation certificate's
   organisation (`O=TEE` or `O=StrongBox`).
2. The resulting chain has five certificates: `root → Droid CA2 → Droid CA3 → attestation → leaf`.

## One Trust Anchor, Many Attestations

An issuer is a small test PKI. Keep it for the lifetime of the suite, register its root once, and issue all test
attestations below it:

```kotlin
--8<-- "GeneratorExamples.kt:generator-anchor"
```

1. To reuse a root, assign `root = RootSpec(certificatePem, privateKeyPkcs8Pem)`. Otherwise, the generator creates one.
2. Explicit issuance times and lifetimes let tests move a chain to whichever unfortunate date is required.
3. Register the root with the test configuration as `TrustedRoot.PublicKey` or `TrustedRoot.Certificate`.

## Negative Test Vectors

Negative tests rarely call for well-behaved input. `mangle` replaces any property with raw ASN.1, allowing the generator
to produce structures that a parser must handle safely and a verifier must reject:

```kotlin
--8<-- "GeneratorExamples.kt:generator-mangled"
```

1. Pass the complete, explicitly tagged property as DER. This example encodes `keySize [3]` with an unexpected nested
   `INTEGER 128`. Invalid encodings are fair game too.

## Command-Line Use

The DSL can export an issuer and its statements to the JSON understood by the
[command-line tool](#attestation-generator). A fixture developed in Kotlin can therefore move into CI unchanged:

```kotlin
--8<-- "GeneratorExamples.kt:generator-config"
```

1. `configuration()` returns a serialisable description of the issuer.
2. A configuration may contain any number of statements; each gets its own certificate chain.
3. Generated root material is included in the configuration. Re-running the command therefore keeps the same trust
   anchor instead of quietly inventing a new PKI.

Configurations are plain JSON. Authorization-list properties contain the complete DER encoding of each property, which
also accommodates invalid values. Warden Supreme's test suite generates and verifies all four examples on every build:

??? example "Minimal Configuration"
    ```json
    --8<-- "generator-minimal.json"
    ```

    You can download this example [here](examples/generator-minimal.json).

??? example "What a TEE-Backed Device Attests to"
    A factory-provisioned TEE chain containing application identity, key parameters, root of trust, OS version, and
    patch level.
    ```json
    --8<-- "generator-tee-factory.json"
    ```

    You can download this example [here](examples/generator-tee-factory.json).

??? example "StrongBox, Provisioned Remotely"
    A remotely provisioned chain with a device-unique attestation and module hash, valid for half an hour.
    ```json
    --8<-- "generator-strongbox-rkp.json"
    ```

    You can download this example [here](examples/generator-strongbox-rkp.json).

??? example "Two Statements That Must Be Rejected"
    One statement replaces `keySize` with valid but unexpected ASN.1. The other reports failed verified boot and carries
    a property outside the schema.
    ```json
    --8<-- "generator-negative-vectors.json"
    ```

    You can download this example [here](examples/generator-negative-vectors.json).

Run the generator with any of these files to write the root certificate and one certificate chain and private key per
statement to `outputDirectory`:

```bash
java -jar attestation-generator.jar generator-tee-factory.json
```

[:material-download: attestation-generator.jar](downloads/attestation-generator.jar){ .md-button }

!!! warning "Test Material Only"
    Generated chains lead to a root created by the generator or supplied in its configuration. They have no connection
    to a Google root and validate only where this test root is explicitly trusted. Keep it out of production
    configuration.
