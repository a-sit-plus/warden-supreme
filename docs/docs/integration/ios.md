# Native iOS Client Integration

!!! info inline end "Preview Status"
    Contrary to KMP clients, the native iOS client has not yet been integrated at scale.
    Hence, rough edges may be present.

Warden Supreme provides a native Swift façade around its Kotlin Multiplatform client. Applications interact with
`IosAttestationClient`, `URL`, `SecKey`, and `SecCertificate`; The Swift package supports iOS 15 and newer.

For the App Attest protocol and verifier-side validation model, see the
[iOS technical deep dive](../technical/ios.md). The general verifier and certificate-issuance setup remains unchanged compared
to regular Kotlin Multiplatform stacks, as per the [end-to-end integration guide](supreme.md).

## Installing the Swift Package

In Xcode, select **File → Add Package Dependencies**, enter
`https://github.com/a-sit-plus/warden-supreme`, select a released version, and add the `WardenSupreme` product to the
application target. Then import it alongside Apple's Security framework:

```swift
import Foundation
import Security
import WardenSupreme
```

## Project and Provisioning Setup

App Attest requires a physical device and an explicit App ID whose bundle identifier matches the app. In the
[Apple Developer portal](https://developer.apple.com/help/account/identifiers/enable-app-capabilities), open
**Certificates, Identifiers & Profiles → Identifiers**, select the App ID, and enable **App Attest**. Regenerate affected
provisioning profiles or let Xcode automatic signing create a new one. Adding only an entitlement file is insufficient
when the selected profile does not contain the capability.

Add **App Attest** under the target's **Signing & Capabilities**, or configure the entitlement directly:

```xml
<key>com.apple.developer.devicecheck.appattest-environment</key>
<string>development</string>
```

Use either `development` or `production` and configure the verifier's iOS `sandbox` setting to match.
Keys are not shared across environments.
TestFlight and App Store builds always use production regardless of the entitlement. See Apple's
[App Attest environment documentation](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.devicecheck.appattest-environment).

Face ID has no separate capability or entitlement. If a challenge can require biometric key protection, add a
user-facing reason to Info.plist; iOS terminates an app that accesses Face ID without one:

```xml
<key>NSFaceIDUsageDescription</key>
<string>Use Face ID to authorize the attested key.</string>
```

To require biometrics without device-passcode fallback, request `biometry = true` and `deviceLock = false` on the Supreme verifier.
Otherwise, user presence may be satisfied by biometrics or the device passcode. Keychain access control is fixed when a key is
created, so use a new alias after changing these constraints. See Apple's
[Face ID usage-description](https://developer.apple.com/documentation/bundleresources/information-property-list/nsfaceidusagedescription)
and [keychain user-presence](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/userpresence)
documentation.

## Performing Attestation
The Swift client caters towards the fully integrated, end-to-end attestation flow and thus comes with a small API
surface. The full client-side therefore only amounts to a few lines of code: 

```swift
let client = IosAttestationClient()
let alias = "account-signing-key"

func attestKey() async throws {

    let result = try await client.performAttestation(
        alias: alias,
        challengeEndpoint: URL(string: "https://verifier.example/api/v1/challenge")!
    )

    guard result.successful else {
        print("Attestation rejected: \(result.message)")
        return
    }
}
```

`performAttestation` fetches the challenge, creates and attests the Signum-backed key, submits the proof to the URL in
the challenge, and stores the returned leaf-first certificate chain under the alias. A verifier rejection is returned as
`IosAttestationResult(successful: false, ...)`; networking, malformed input, and platform failures are thrown.

Accessing the attested key, the certificate chain or even just the leaf certificate
is straight forward as well:

```swift
let privateKey: SecKey = try await client.getAttestedKey(alias: alias)
let leaf: SecCertificate? = client.getAttestationKeyCertificate(alias: alias)
let chain: [SecCertificate] = client.getAttestationCertificateChain(alias: alias)
```

`getAttestedKey` is asynchronous because retrieving a protected key can display Face ID or another system authentication
prompt. It returns a native `SecKey`; the leaf and complete-chain APIs return native `SecCertificate` values. The private
key never leaves the secure enclave.  
Creating another key under an existing alias fails, so key lifecycle and alias selection
remain the application's responsibility.

### Networking and Certificate Pinning

The client permits cellular access by default. It can be disabled, and HTTPS certificate pins can be supplied in Ktor's
`sha256/<base64>` format:

```swift
let client = IosAttestationClient(
    allowCellularAccess: false,
    pins: [
        PinnedCertificate(
            domain: "verifier.example",
            fingerprints: ["sha256/BASE64_SHA256_CERTIFICATE_FINGERPRINT"]
        )
    ]
)
```

!!! warning "Trust the challenge endpoint"
    The initial challenge fetch is unauthenticated and its response controls the attestation ceremony and proof endpoint.
    Use HTTPS to a verifier you trust and configure certificate pinning where appropriate.

### Client-Provided Attributes

If the verifier requests additional attributes, use the overloaded `performAttestation` function
that expects an `additionalAttributes` callback. The callback receives the
requested name, primitive type, and whether the value is required:

```swift
let result = try await client.performAttestation(
    alias: alias,
    challengeEndpoint: verifierURL,
    additionalAttributes: { requests in
        requests.map { request -> AttestedAttributeValue? in
            switch (request.name, request.type) {
            case ("employeeId", .string):
                .string(currentUser.employeeId)
            case ("managedDevice", .boolean):
                .boolean(true)
            default:
                nil
            }
        }
    }
)
```

Return exactly one value per request and preserve their order. Use `nil` only to omit an optional attribute; a missing
required attribute or a value whose case does not match the requested type causes `performAttestation` to throw. The
overload without `additionalAttributes` behaves as if every requested value were `nil`.

### Plain HTTP During Local Development

`performAttestation` accepts HTTP URLs, but App Transport Security blocks plain HTTP unless the application opts out. For
a debug-only app that connects directly to a verifier on the development machine, add these keys to Info.plist and use
the machine's LAN address, not `localhost`:

```xml
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
</dict>
<key>NSLocalNetworkUsageDescription</key>
<string>Connect to the local Warden Supreme verifier.</string>
```

Bind the server to a LAN interface and allow it through the host firewall. Remove the ATS exception from release builds
and use HTTPS for every non-local deployment.

## Technical Details
The Swift client still relies on KMP and merely provides a façade around the Supreme Kotlin Multiplatform client.
In the age of AI-assisted vulnerability analysis, this is not at all about easy wins and very much so at the same time:

* A pure Swift re-implementation of the Supreme verifier would be much more light-weight.
* However, it would also come with the added cost of maintaining and hardening two disjoint stacks, meaning that
  any vulnerability found in the KMP codebase would require follow-up analysis of the Swift code and vice versa. This entails:
    * Longer release/hotfix cycles
    * Increased complexity and higher potential for bugs
    * Hardening two serialization stacks, which is an intriguing challenge as it is a steady stream of bugs old and new, but not the right call for security-critical functionality.

Keeping Swift-client-specific code do nothing more but a thin façade, allows focused development and hardening effort to be spent
on a single KMP codebase. Hence it is more than just an easy win in terms of not having to develop and maintain two disjoint stacks,
but a deliberate, informed choice.
Hence, there will never be an official re-implementation of the Supreme client functionality in Swift.

## Demonstrator App

The repository contains a complete SwiftUI demonstrator in
[`iosTest/WardenTest`](https://github.com/a-sit-plus/warden-supreme/tree/main/iosTest/WardenTest). It can attest a new
key against a Supreme verifier, retrieve the native `SecKey`, sign user-entered text, and verify the signature with the
public key from the returned leaf certificate.

The Xcode project references the locally built XCFramework and Gradle wrapper through relative paths. Its build phase
automatically runs `:supreme-client-swift:assembleWardenSupremeXCFramework`; no adjustment of paths is needed, as no absolute
paths are used.

Before running the demonstrator on an iPhone:

1. Change the bundle identifier to one you control.
2. Select your Apple development team.
3. Enable App Attest for the matching explicit App ID and refresh its provisioning profile.
4. Set the App Attest environment in `WardenTest.entitlements` to match the verifier configuration.
5. Enter the verifier's absolute challenge URL in the app.

The demo targets iOS 16 because its UI uses `NavigationStack`, while the distributed framework itself supports iOS 15.
App Attest cannot run in the simulator.

