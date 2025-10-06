# Quirks, bugs, workarounds, and hints

Warden Supreme's unified Android and iOS attestation core, _Warden_, has been used in production for years and attested millions of clients.
Naturally, this caused hiccups but also enabled the collection of these hiccups' causes.
Due to the diversity of its device landscape, Android is most affected by this. iOS, however, is also not without flaws.

This page lists known quirks and bugs, and discusses how to deal with them.
First, however, some general hints that apply regardlessly are discussed.

## General hints
Using attestation to strongly enforce policies and to remotely establish trust in mobile clients is rooted in cryptographic
mechanisms and PKI procedures.
Hence, timeliness is of the essence, freshness windows and temporal checks are crucial.
As a logical consequence, the clocks between a service and to-be-attested clients need to be in sync.

Given that the service owner is very much not the device owner, clock drifts and even timezone differences causing hours of
offset are not uncommon.
Warden Supreme allows for sending server time zone (and even clock drift information) to clients along with a cryptographic nonce
at the start of an attestation procedure.
However, cryptographic operations are performed in hardware and are thus not controlled by the application that receives
the attestation challenge.
A timezone offset and a time drift will therefore result in a certificate chain carrying attestation statements that will
error out due to temporal offsets. There are two generic ways to cope with this, as discussed in the following subsections.

### Increasing temporal leeway
Warden's Supreme verifier allows for setting a global verification clock offset through the parameter `verificationTimeOffset`.
**You will always want to set this, because even one millisecond of clock drift can cause otherwise perfectly valid attestations to error out!**  
In addition, there are two parameters (one for iOS, and one for Android-specific configuration), both called `attestationStatementValiditySeconds`,
and both defaulting to five minutes.

!!! danger "The two Sources of Attestation Creation Time"
    iOS and Android attestation statements come with two kinds of temporal validity:

    1. The (leaf) certificates `notBefore` and `notAfter` validity period
    2. An attestation creation time, encoded into the attestation data (this is true for iOS and Android)
    
    Both values need to be temporally valid for an attestation to verify!

Given the criticality of these parameters and the need to override them naturally raises the question of why there's no sane default.
The answer is twofold: On the one hand, Apple recommends certain validity durations, and setting an offset will require overriding the default five minutes
with a longer value. This, however, then results in a freshness window that might go against Apple's recommendation.
The second part of the answer relates to Android, or rather, bugs in the Keystore, vendor-specific code paths, and firmware.

### Partially Ignoring Temporal Checks
iOS's attestation implementation is mostly sane, with proper certificate validity and an always present attestation creation time.
The diversity of Android implementations, however, leads to a form of anarchy
that undermines some requirements for attestation checks.
This means that setting a global verification clock offset, and increasing the iOS-specific `attestationStatementValiditySeconds` by said offset is usually enough to pacify
Warden's iOS attestation checking routines, but Android requires more tweaking.

In fact, if you want to ensure that as many Android devices as possible will pass attestation checks, you need to set
the following configuration parameters:

* `AndroidAttestationConfiguration.ignoreLeafValidity = true`
* `verificationTimeOffset = 5.minutes`
* `AndroidAttestationConfiguration.attestationStatementValiditySeconds = null`

If you assume that this completely disables temporal validity checks on Android attestation statements, you'd be correct.
On its own, this configuration will result in an infinite freshness window, effectively removing crucial freshness guarantees, which
can make it significantly easier to mount certain targeted attacks. Of course, nobody wants that.

!!! note inline end
    Warden Supreme does not supply a component issuing, checking, and invalidating challenges, and some deployments
    require rather elaborate nonce handling.

Luckily, freshness is not solely tied to synchronized clocks, but each attestation statement must include a challenge issued
by the service. **Hence, if your challenge is an unpredictable cryptographic nonce based in true randomness**, you can get
away with ignoring all temporal characteristics of the leaf certificate containing the Android attestation data –
**Iff you make your challenges expire after a couple of minutes, ensure that a nonce truly is a value only used once,
and that they are invalidated once used!**

This closes the circle on the question of why integrators are required to manually specify all this: Care must be taken, 
and constraints on the challenge must be fulfilled before fiddling with temporal validity checks.

## Android

!!! tip inline end "Fundamental Requirements"
    Only Google Play certified devices (i.e. those bearing the official Android branding) support remote attestation.
    Huawei devices, for example, or Chinese import devices that do not come with Google Play services out-of-the-box cannot be attested!

Even though the previous section dealt with a crucial Android-specific issue, there's (sadly) more, and
Android bugs fall into three categories:

1. Encoding flaws, affecting the byte representation of attestation information
2. OS bugs, and vendor quirks, affecting the behaviour of devices
3. Non-obvious, but deliberate design decisions

### Encoding Flaws

#### Creation Time issues
Some (especially older) Android devices do not encode an attestation creation time, and always encode zero seconds since
the epoch into the leaf certificate's `notBefore` **and** `notAfter`. This is partially by design, but some devices
continue to do this, even though they should very much not.

#### ASN.1 Time Bugs
Some vendors encode **UTC Time vs. GeneralizedTime** incorrectly leading to years of temporal offset.
Only the vendor can fix this though updates. However, relying on a tight freshness window based on a cryptographic nonce
sourced from true randomness is recommended anyway (see [Partially Ignoring Temporal Checks](#partially-ignoring-temporal-checks)).

### Vendor Patch level misencoding
Many **Android 15** devices (even emulator images) and some Samsung devices do not conform to the ASN.1 schema for attestation data wrt. patch level encoding.
This concerns the vendor patch level field, not the OS patch level, and requires monkey-patching Google's upstream parser code to prevent it from glitching out.
**Warden Supreme already applies the necessary band-aids**, but enforcing vendor patch levels is generally discouraged in favour of OS patch levels.

### OS Bugs and Quirks

#### Bootloader Unlock Destroying Keys
Many devices **destroy keys** or make attestation impossible after a bootloader unlock. There is nothing to be done about this, and even relocking often cannot bring back
cryptographic keys sent to nirvana!
While **technically** not a violation of the Android certification requirements, it very much is bad practice at the vendor's end.
This is especially hard to swallow for device owners, since buying a new device is the only thing that can be done about this. Known affected devices:

- Fairphone 2
- Nothing Phone 3a
- There are definitely others

#### Keystore2 binder bug
On rare occasions, attestation fails because the connection between the Keystore and the package manager breaks up. While the bug has been identified and fixed, it will only land in Android 17 (see commit [b0be7edbf9e3…](https://android.googlesource.com/platform/system/security/+/b0be7edbf9e34bc409c6d869f936c2eb00925b34)).
This bug manifests itself by listing `UnknownApplication` instead of a proper application package in the attestation statement. Rebooting the device helps.

### Deliberate Design Decisions

#### Revocation
The certificate chains created by Android use neither CRL nor OCSP, but a custom scheme. Hence, back-end services must be able to reach Google's servers hosting the revocation information.
Warden Supreme allows for specifying an HTTP proxy URL, to facilitate setups behind a proxy.

#### Temporally Invalid Leaf Certificates
As mentioned in [Partially Ignoring Temporal Checks](#partially-ignoring-temporal-checks), many older Android devices do not encode a sensible validity into the leaf certificate carrying
attestation information. This was a deliberate choice by Google, that has since been reversed. Some vendors still adhere to this practice, though.

#### Remote provisioning
Newer Android devices support remote key provisioning and even require key rollover. Hence, offline devices can **exhaust key pools**, causing transient attestation failures. Taking devices online fixes this issue.
The issue manifest itself on the client as `r#ERROR_PENDING_INTERNET_CONNECTIVITY 2: Error::Rc(r#OUT_OF_KEYS_PENDING_INTERNET_CONNECTIVITY)) (public error code: 16 internal Keystore code: 24)`

#### PKIX Certificate Path Quirks
Especially older Android versions deliberately botched the certificate path leading from the leaf certificate to a Google root certificate.
This was done to prevent those certificate chains from being used for TLS certificates.
Warden Supreme includes a manual check **and** Google's custom PKIX certificate path validator introduced with the new upstream attestation library

## iOS

### Online Requirement and Rate Limiting
iOS requires an internet connection **on the mobile device** to issue attestations, as it needs to talk to an Apple service.
This service is subject to rate limiting (see [Preparing to use App Attest](https://developer.apple.com/documentation/devicecheck/preparing-to-use-the-app-attest-service)). **Keep this in mind!**

### Non-Compliant ASN.1 SET OF
The custom certificate extension carrying some attestation information uses `SET OF` for some parameters. Apple failed to observe the constraints DER-encoded ASN.1 data must fulfil
and did not sort the members of this set as required.
Warden Supreme relies on a lenient ASN.1 parser that does not get tripped by this. If you are processing iOS attestation using other stacks, this could cause issues, though.
