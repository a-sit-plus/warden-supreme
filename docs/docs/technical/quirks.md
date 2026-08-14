# Quirks, Bugs, Workarounds, and Hints

_Makoto_, Warden Supreme's unified Android and iOS attestation core, has attested millions of clients over several years
of production use. This exposed the edge cases documented here. Android accounts for most of them because its device
ecosystem is considerably more varied; iOS contributes a smaller but still noteworthy collection of constraints and
implementation defects.

This page lists known quirks and bugs, starting with guidance that applies across platforms.

## Configuration Loading

Warden Supreme's supported configuration loading integrations are the canonical readers themselves (`fromJsonString()`,
`fromYamlString()`, `fromJsonObject()`, file helpers on JVM), the Hoplite decoder from `config-hoplite`, and the Spring
`Environment` bridge from `config-spring`.

The Hoplite and Spring helper modules delegate back into the canonical configuration readers, so validation and defaults
still happen in exactly one place.

### YAML Parsing Caveats

This is not specific to Spring. It applies equally to native YAML loading, Hoplite, and Spring-backed YAML config.

* **Quote string properties whose plain YAML form can be interpreted as numbers.**
  For example, iOS build numbers such as `"21E236"` must remain quoted, otherwise YAML may parse them as a number before
  Warden Supreme sees the value.

### Spring Loading Quirks

The Spring bridge is tested for nested prefixes, indexed collection binding, profile overrides, property-source
precedence, and `spring.config.import` composition. A few Spring-specific caveats are still worth documenting:

* **Prefer prefix-based loading from Spring config files, property maps, or imported config trees.**
  `fromSpringEnvironment(env, "your.prefix")` and `fromSpringMap(map)` are the intended integration points.
* **Do not rely on Spring-backed loading for explicit `null` overrides.**
  This limitation applies to `fromSpringEnvironment(...)` and, in practice, usually also to `fromSpringMap(...)` when
  that map came from Spring's own binder or config parsing. Spring frequently normalises explicit `null` to the same
  effective state as a missing property before Warden Supreme sees the data. As a result, non-null defaults generally
  cannot be overridden with `null` through the Spring integration path.
* **If you need exact `null` semantics, use the canonical readers directly.**
  Prefer `fromYamlString(...)`, `fromJsonString(...)`, `fromYamlFile(...)`, or `fromJsonFile(...)` for configurations
  where explicit `null` must survive unchanged until Warden Supreme decodes them.
* **Do not rely on raw environment-variable binding into the Spring map bridge.**
  Spring's environment-variable normalisation can split property-name segments such as `packageName` or
  `signerFingerprints` in ways that do not round-trip into the raw `Map<String, Any?>` structure used by
  `config-spring`. In practice, names like `PACKAGE_NAME` or `SIGNER_FINGERPRINTS` are not a stable contract here.
* **If you need system-environment-based configuration, prefer pointing Spring at a YAML/JSON config file or another
  Spring-supported config source, and then load via `fromSpringEnvironment(...)` from the resolved prefix.**

## General Hints
Attestation depends on certificate validity, attestation timestamps, challenge freshness, and the clocks used to
evaluate them. The server and client keep independent clocks, so drift must be accommodated without weakening replay
protection.

Clock drift and time-zone offsets of several hours occur on devices outside the service operator's control. Warden
Supreme sends the server time zone and detected drift to the client alongside the nonce at the start of a ceremony.
Cryptographic hardware still uses the device clock, outside the control of the application receiving the challenge. A
badly configured clock can therefore produce a certificate chain or attestation statement that fails temporal checks.

### Clock Drifts and Temporal Validity
!!! danger "Time is relative (literally)!"
    Three components require a time source (irrespective of Warden Supreme's implementation):
        
    * iOS attestation verification
    * Android attestation verification
    * The component ensuring freshness, guarding both of the above
    
    Two independent system clocks remain:
    
    * The back-end, verifying attestation proofs (CSRs)
    * Mobile clients, issuing those proofs to begin with
    
    This complexity is inherent. Warden Supreme's defaults accommodate the usual drift and hide it for most
    deployments. Changing them requires understanding how certificate validity, attestation creation time, and nonce
    expiry interact.

Warden Supreme's verifier allows for setting a global verification clock offset through the parameter `verificationTimeOffset`.

* The default is five minutes because any positive drift can make an otherwise valid attestation appear premature.
* Those five minutes are added to Apple's recommended default lifetime of an iOS attestation, effectively increasing the
  maximum age of an attestation that is still considered valid by five minutes.


!!! danger "The Two Sources of Attestation Creation Time"
    iOS and Android attestation statements come with two kinds of temporal validity:
    
    1. The (leaf) certificates `notBefore` and `notAfter` validity period
    2. An attestation creation time, encoded into the attestation data (this is true for iOS and Android)
    
    These values need to be temporally valid for an attestation to verify **in addition to nonce validity**!

iOS's attestation implementation is mostly sane, with proper certificate validity and an always present attestation creation time.
The diversity of Android implementations, however, leads to a form of anarchy
that undermines some requirements for attestation checks.
In fact, many Android devices mess up a correctly encoded certificate validity, or the
attestation statement validity, **or both**.

Luckily, this can be worked around **if and only if challenges issued by the back-end expire after a couple of minutes and are rooted in a truly random value only used once,
that is invalidated once used.**

!!! note "Warden Supreme Default Behaviour"
    Warden Supreme also ships with a default nonce generation service and a challenge validation component that follows this strategy.
    Hence, Warden Supreme behaves as follows by default:
    
    * Adding a five-minute verification time offset
    * Using the recommended default validity of iOS attestation statements **plus that five-minute offset**
    * Generating truly random nonces that expire after this very same iOS validity
    * Completely disabling the validity checks on the leaf certificate and the encoded attestation statement validity period on Android.

These defaults preserve the relevant security properties because Warden Supreme validates the challenge **before it
parses the attestation proof**.
In addition, Warden Supreme communicates nonce validity periods to clients.
The validity period encoded into challenges is shifted by the inverse verification time offset, because clients see the drift in the opposite direction.
Communicating this information to clients has the inherent benefit that large clock drifts can be caught right away and communicated to the user.

??? warning "Changing Defaults"
    It is perfectly possible to tweak this behaviour, if desired, but do keep all the above complexity in mind and **do not turn this into a footgun** by making changes lightly!

## Android

!!! tip inline end "Fundamental Requirements"
    Only devices that **launched as GMS-certified (Play Protect certified)** support remote attestation rooted in Google’s attestation trust anchors.
    Devices that did not launch with a GMS license (for example many Huawei devices, Amazon Fire OS devices, or China-market variants that ship without Google Play services) typically **cannot** be validated against the Google root of trust.
    **Sideloading Google Play services later does not change this.**
    
    Whether a **GMS-certified device that was later modified** (bootloader unlock, custom ROM, rooted system, etc.) is “untrusted” is a **policy decision**: the attestation evidence exposes boot state and related signals, and your verifier decides what to accept.

Android bugs fall into three categories:

1. Encoding flaws affecting the byte representation of attestation information
2. OS bugs and vendor quirks affecting the behaviour of devices
3. Non-obvious, but deliberate design decisions

### Encoding Flaws

#### Creation Time Issues
Some (especially older) Android devices do not encode an attestation creation time, and always encode zero seconds since
the epoch into the leaf certificate's `notBefore` **and** `notAfter`. This is partially by design, but some devices
continue to do this, even though they should very much not.

#### ASN.1 Time Bugs
Some vendors encode **UTC Time vs. GeneralizedTime** incorrectly leading to years of temporal offset.
Only the vendor can fix this through updates. However, relying on a tight freshness window based on a cryptographic nonce
sourced from true randomness is recommended anyway (see [Clock Drifts and Temporal Validity](#clock-drifts-and-temporal-validity)).

#### Malformed DER Encoding of Certificates
Some vendors even fail properly encoding DER BOOLEANs. Warden Supreme is lenient about this, but if you are using a strict
DER decoder, this might trip it.

#### Duplicate `AuthorizationList` Tags on Android 16
Some Android 16 devices emit non-compliant attestation `AuthorizationList` structures containing multiple entries with
the same tag. The tried-and-true legacy Google parser, which Warden Supreme currently uses by default, rejects these structures and therefore
cannot verify affected devices.

Warden Supreme's own _supreme_ parser handles repeated tags without silently choosing one value:

- If every entry with the same tag has the same value, the parser reports that value.
- If the entries disagree, reading that property returns an error instead of trusting an arbitrary entry.

This behaviour prevents conflicting security-relevant values from overriding one another, as described in
[GHSA-rxrw-2p38-wfmr](https://github.com/a-sit-plus/warden-supreme/security/advisories/GHSA-rxrw-2p38-wfmr), and
was fixed in Warden Supreme 1.0.3. The Supreme parser is planned to become the default in a future release and can
already be enabled by setting `supremeParser = true` in the Android attestation configuration (which is generally recommended,
but not the default for compatibility reasons).

#### Patch Level Misencoding
Date encoding should be unremarkable. Production certificates prove otherwise.

##### Vendor Patch Level Misencoding
Many **Android 15** devices (even emulator images) do not conform to the ASN.1 schema for attestation data with respect to patch level encoding.
This concerns the **vendor patch level** field (not the OS patch level) and can cause Google's upstream parser to fail unless it is patched to be more tolerant.
**Warden Supreme already applies the necessary band-aids**, but enforcing vendor patch levels is generally discouraged in favour of OS patch levels.

The issue typically manifests as the vendor patch level being encoded as `0`.
The most likely root cause is a faulty reference implementation by Google (as evidenced by emulator images exhibiting the same behaviour) that was adopted by OEMs and shipped in both factory images and over-the-air updates.

##### Patch Level Truncation
Some devices truncate `vendorPatchLevel` and/or `bootPatchLevel` by omitting the day-of-month.
Instead of the expected `yyyyMMdd` form (e.g. `20181230`), they encode only `yyyyMM` (e.g. `201812`).
This does not conform to the attestation extension schema and needs to be handled leniently (e.g. by treating a missing day as unknown/default and avoiding strict enforcement of these fields).

##### Patch Level Off-By-One Errors
There are also devices that encode invalid “zero” date components: some encode the first day of a month as `00` instead of `01`, and some even encode January as `00` instead of `01`.
Both variants violate the expected `yyyyMMdd`/`yyyyMM` semantics and need the same kind of lenient handling.

#### Broken RSA PKCS#1 `AlgorithmIdentifier` (Missing ASN.1 NULL)
Some Android devices generate a non-conforming X.509 leaf certificate **at attestation time**.
When the app requests key attestation, the device creates a leaf certificate carrying the attestation proof and signs it
inside the TEE. On affected devices, this newly generated certificate is not fully X.509/DER-conforming.

Concretely, for RSA PKCS#1 v1.5 signature algorithms, the X.509 ASN.1 profile requires `AlgorithmIdentifier.parameters` to be present and encoded as ASN.1 `NULL` (`05 00`).
On affected devices, the certificate’s signature algorithm is encoded as an `AlgorithmIdentifier` that contains only the OID and omits the required `NULL` parameters.
A common case is `sha256WithRSAEncryption` with OID `1.2.840.113549.1.1.11`, encoded as:

- **illegal (missing NULL):** `30 0b 06 09 2a 86 48 86 f7 0d 01 01 0b`
- **required by X.509 profile:** `30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00`

Many parsers accept this encoding, but strict implementations may reject the certificate or fail when comparing
signature algorithm identifiers byte-for-byte. Android attestation parsing must accommodate it.

#### Broken Certificate Extension Encoding (Explicit `critical = false`)
Some devices produce attestation certificates whose extension encoding is not DER-compliant: they explicitly encode the `critical` flag as `false` inside the attestation extension, instead of omitting it.

Per RFC 5280, an X.509 extension is defined as `SEQUENCE { extnOID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }`.
In DER, values that are equal to their ASN.1 `DEFAULT` **must be omitted** from the encoding.
Encoding `critical = false` therefore violates RFC 5280 (and, by extension, the expectation that certificate chains are DER-encoded).

Devices producing such certificates should not have passed GMS certification. They nevertheless exist in large numbers,
so a production verifier must treat an explicitly encoded `critical = false` as equivalent to an omitted default.

### Misleading Assumptions about ECDH
Virtually every Android device supports hardware-backed EC crypto and EC Diffie-Hellman key agreement.
**However**, this does not entail that it supports a combination of the two. With respect to EC keys, only ECDSA signatures on NIST curves
are guaranteed to be performed in hardware, assuming a cryptographic hardware module. This means that without explicitly specifying
[KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT](https://developer.android.com/reference/android/security/keystore/KeyProperties#SECURITY_LEVEL_TRUSTED_ENVIRONMENT)
during key generation, even generating an EC key pair for a curve supported in hardware may lead to a key being actually generated
in software, as soon as [KeyProperties.PURPOSE_AGREE_KEY](https://developer.android.com/reference/android/security/keystore/KeyProperties#PURPOSE_AGREE_KEY)
is also set.

### OS Bugs and Quirks

#### Bootloader Unlock Destroying Keys
Many devices **destroy keys** or make attestation impossible after a bootloader unlock. There is nothing to be done about this, and even relocking typically cannot restore
cryptographic keys. Hence, this issue manifests itself **on the client device**.
While **technically** not a violation of Android device certification requirements, it very much is bad practice at the vendor's end.
This is especially hard to swallow for device owners, since buying a new device is the only thing that can be done about this. Known affected devices:

- Fairphone 2
- Nothing Phone 3a
- There are likely others

#### Keystore2 Binder Bug
On rare occasions, attestation fails because the connection between the Keystore and the package manager breaks up. While the bug has been identified and fixed, it will only land in Android 17 (see commit [b0be7edbf9e3…](https://android.googlesource.com/platform/system/security/+/b0be7edbf9e34bc409c6d869f936c2eb00925b34)).
This bug manifests itself by listing `UnknownApplication` instead of a proper application package in the attestation statement. Rebooting the device helps.

### Deliberate Design Decisions

#### Revocation
The certificate chains created by Android use neither CRL nor OCSP, but a custom scheme. Hence, back-end services must be able to reach Google's servers hosting the revocation information.
Warden Supreme allows specifying an HTTP proxy URL for setups behind a proxy.
In addition, custom sources of revocation information are supported.

#### Temporally Invalid Leaf Certificates
As mentioned in [Clock Drifts and Temporal Validity](#clock-drifts-and-temporal-validity), many older Android devices do not encode a sensible validity into the leaf certificate carrying
attestation information. This was a deliberate choice by Google, that has since been reversed. Some vendors still adhere to this practice, though.

#### Remote Provisioning
Newer Android devices support remote key provisioning and even require key rollover. Hence, offline devices can **exhaust key pools**, causing transient attestation failures. Taking devices online fixes this issue.
The issue manifests itself **on the client device** as `r#ERROR_PENDING_INTERNET_CONNECTIVITY 2: Error::Rc(r#OUT_OF_KEYS_PENDING_INTERNET_CONNECTIVITY)) (public error code: 16 internal Keystore code: 24)`
when trying to create an attestation statement.

#### PKIX Certificate Path Quirks
Especially older Android versions deliberately botched the certificate path leading from the leaf certificate to a Google root certificate.
This prevents attestation certificate chains from being used for TLS certificates (which you should not do, anyway).
Warden Supreme includes a manual check **and** Google's custom PKIX certificate path validator introduced with the new upstream attestation library.
If you need a certificate chain that works for TLS, issue your own for an attested key (see [Integration Guide](../integration/supreme.md)).

## iOS

### Online Requirement and Rate Limiting
iOS requires an internet connection **on the mobile device** to issue attestations, as it needs to talk to an Apple service.
This service is subject to rate limiting (see [Preparing to Use App Attest]({{ links.ios_preparing_app_attest }})). **Keep this in mind!**

### Non-Compliant ASN.1 SET OF
The custom certificate extension carrying some attestation information uses `SET OF` for some parameters. Apple failed to observe the constraints DER-encoded ASN.1 data must fulfil
and did not sort the members of this set as required.
Warden Supreme relies on a lenient ASN.1 parser that does not get tripped by this. If you are processing iOS attestation using other stacks, this could cause issues, though.
