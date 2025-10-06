# Debugging, Recording, and Replaying Attestation Checks
Whenever the actual attestation check fails (i.e., whenever `onAttestationError()` is called), a ready-made `WardenDebugAttestationStatement` is created and passed to this function.
Hence, two pieces of information are available to aid debugging:

1. the attestation error (as the receiver of this lambda)
2. the debug statement, which can be exported for off-site analyses

## Debugging Integrated Attestation

The `WardenDebugAttestationStatement` can be serialized to JSON by invoking `.serialize()` (or `serializeCompact()`) on it.
It can later be deserialized by calling `deserialize()` (or `deserializeCompact()`) on its companion.
By finally calling `replaySmart()` on such a deserialized debug info object, the whole attestation verification process is replayed.

Attaching a debugger allows for step-by-step debugging of any attestation errors encountered.
For the most straightforward debugging experience:

* import this project into IDEA
* add a breakpoint [here in line 19](https://github.com/a-sit-plus/warden-supreme/tree/main/utils/makoto-diag/src/main/kotlin/Diag.kt#L19)
* and run it in debug mode.

Just be sure to add a single argument pointing to a file as described in [Diag.kt](https://github.com/a-sit-plus/warden-supreme/tree/mainutils/makoto-diag/src/main/kotlin/Diag.kt)!

## Debugging Raw Android Attestations
A similar utility exists for printing the contents of an Android attestation statement, located in [/utils/roboto-diag](https://github.com/a-sit-plus/warden-supreme/tree/mainutils/roboto-diag).
More specifically, it pretty-prints the contents of the leaf certificate's Android attestation extension and expects either

* `-f path/to/leaf/certificate.pem`
* a base64-encoded certificate as the sole argument

It will then serialize a certificate to JSON, giving insight into the attestable properties.