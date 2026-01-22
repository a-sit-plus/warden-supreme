# Quirks, Bugs, Workarounds, and Hints

Warden Supreme's unified Android and iOS attestation core, _Makoto_ (formerly _WARDEN_), has been used in production for years and attested millions of clients.
Naturally, this caused hiccups but also enabled the collection of these hiccups' causes.
Due to the diversity of its device landscape, Android is most affected by this. iOS, however, is also not without flaws.

This page lists known quirks and bugs, and discusses how to deal with them.
First, however, some general hints that apply regardlessly are discussed.

## General Hints
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
error out due to temporal offsets (see below).

### Clock Drifts and Temporal Validity
!!! danger "Time is relative (literally)!"
    Three components require a time source (irrespective of Warden Supreme's implementation):
        
    * iOS attestation verification
    * Android attestation verification
    * The component ensuring freshness guarding both of the previous
    
    Of course, this still leaves two entities with system clocks that are isolated from each other:
    
    * The back-end, verifying attestation proofs
    * Mobile clients, issuing those proofs to begin with
    
    **Theis complexity is inherent** and nothing can be done to simplify this situation on a conceptual level, but
    Warden Supreme provides sane defaults that have proven to work well in practice.  
    This means that for 99% of all deployments, this complexity is hidden away, but if you need to change the defaults
    **you will need to get your hands dirty and entertain thoughts about this mess!**

Warden's Supreme verifier allows for setting a global verification clock offset through the parameter `verificationTimeOffset`.

* **This defaults to five minutes, because even one millisecond of clock drift can cause otherwise perfectly valid attestations to error out!**
* Those five minutes are added to Apple's recommended default lifetime of an iOS attestation, effectively increasing the
  maximum age of an attestation that is still considered valid by five minutes.


!!! danger "The two Sources of Attestation Creation Time"
    (Yes, things get even more complex!)  
    iOS and Android attestation statements come with two kinds of temporal validity:

    1. The (leaf) certificates `notBefore` and `notAfter` validity period
    2. An attestation creation time, encoded into the attestation data (this is true for iOS and Android)
    
    These values need to be temporally valid for an attestation to verify **in addition to nonce validity**!

iOS's attestation implementation is mostly sane, with proper certificate validity and an always present attestation creation time.
The diversity of Android implementations, however, leads to a form of anarchy
that undermines some requirements for attestation checks.
In fact, many Android devices mess up a correctly encoded certificate validity, or the
attestation statement validity, **or both**.

Luckily, this can be worked around **iff challenges issued by the back-end expire after a couple of minutes, and iff they are rooted in a truly random value only used once,
that is invalidated once used!**

!!! note "Warden Supreme Default Behaviour"
    Warden supreme also ships with a default nonce generation service and a challenge validation component that follows this strategy.
    Hence, Warden Supreme behave as follows by default:
    
    * Adding a five minute verification time offset
    * Using the recommended default validity of iOS attestation statements **plus that five minute offset**
    * Generating truly random nonces that expire after this very same iOS validity
    * Completely disabling the validity checks on the leaf certificate and the encoded attestation proof validity period on Android.

The Warden Supreme defaults do not have any adverse impact on security that matters in practice
because Warden Supreme checks the validity of challenges **before an attestation proof is even parsed**.
In addition, Warden Supreme communicates nonce validity periods to clients.
The validity period encoded into challenges is shifted by the inverse verification time offset, as the clients have an inverse view on relative clock drifts between back-end and themselves.
Communicating this information to clients has the inherent benefit that large clock drifts can be caught right away and communicated to the user.

??? warning "Changing Defaults"
    It is perfectly possible to tweak this behaviour, if desired, but do keep all the above complexity in mind and **do not turn this into a footgun** by making changes lightly!

## Android

!!! tip inline end "Fundamental Requirements"
    Only Google Play certified devices (i.e. those bearing the official Android branding) support remote attestation.
    Huawei devices, for example, or Chinese import devices that do not come with Google Play services out-of-the-box cannot be attested!

Even though the previous section dealt with a crucial Android-specific issue, there's (sadly) more, and
Android bugs fall into three categories:

1. Encoding flaws affecting the byte representation of attestation information
2. OS bugs, and vendor quirks, affecting the behaviour of devices
3. Non-obvious, but deliberate design decisions

### Encoding Flaws

#### Creation Time Issues
Some (especially older) Android devices do not encode an attestation creation time, and always encode zero seconds since
the epoch into the leaf certificate's `notBefore` **and** `notAfter`. This is partially by design, but some devices
continue to do this, even though they should very much not.

#### ASN.1 Time Bugs
Some vendors encode **UTC Time vs. GeneralizedTime** incorrectly leading to years of temporal offset.
Only the vendor can fix this though updates. However, relying on a tight freshness window based on a cryptographic nonce
sourced from true randomness is recommended anyway (see [Clock Drifts and Temporal Validity](#clock-drifts-and-temporal-validity)).

#### Vendor Patch Level Misencoding
Many **Android 15** devices (even emulator images) and some Samsung devices do not conform to the ASN.1 schema for attestation data wrt. patch level encoding.
This concerns the vendor patch level field, not the OS patch level, and requires monkey-patching Google's upstream parser code to prevent it from glitching out.
**Warden Supreme already applies the necessary band-aids**, but enforcing vendor patch levels is generally discouraged in favour of OS patch levels.

### Misleading Assumptions about ECDH
Virtually every Android device supports hardware-backed EC crypto and EC Diffie-Hellman key agreement.
**However**, this does not entail that it supports a combination of the two. With respect to EC keys, only ECDSA verification on NIST curves
is guaranteed to be performed in hardware, assuming a cryptographic hardware module. This means that without explicitly specifying
[KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT](https://developer.android.com/reference/android/security/keystore/KeyProperties#SECURITY_LEVEL_TRUSTED_ENVIRONMENT)
during key generation, even generating an EC key pair for a curve supported in hardware may lead to a key being actually generated
in software, as soon as [KeyProperties.PURPOSE_AGREE_KEY](https://developer.android.com/reference/android/security/keystore/KeyProperties#PURPOSE_AGREE_KEY)
is also set.

### OS Bugs and Quirks

#### Bootloader Unlock Destroying Keys
Many devices **destroy keys** or make attestation impossible after a bootloader unlock. There is nothing to be done about this, and even relocking typically cannot bring back
cryptographic keys sent to nirvana! Hence, this issue manifests itself **on the client device**.
While **technically** not a violation of the Android certification requirements, it very much is bad practice at the vendor's end.
This is especially hard to swallow for device owners, since buying a new device is the only thing that can be done about this. Known affected devices:

- Fairphone 2
- Nothing Phone 3a
- There are definitely others

#### Keystore2 Binder Bug
On rare occasions, attestation fails because the connection between the Keystore and the package manager breaks up. While the bug has been identified and fixed, it will only land in Android 17 (see commit [b0be7edbf9e3…](https://android.googlesource.com/platform/system/security/+/b0be7edbf9e34bc409c6d869f936c2eb00925b34)).
This bug manifests itself by listing `UnknownApplication` instead of a proper application package in the attestation statement. Rebooting the device helps.

### Deliberate Design Decisions

#### Revocation
The certificate chains created by Android use neither CRL nor OCSP, but a custom scheme. Hence, back-end services must be able to reach Google's servers hosting the revocation information.
Warden Supreme allows for specifying an HTTP proxy URL, to facilitate setups behind a proxy.

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
This service is subject to rate limiting (see [Preparing to use App Attest](https://developer.apple.com/documentation/devicecheck/preparing-to-use-the-app-attest-service)). **Keep this in mind!**

### Non-Compliant ASN.1 SET OF
The custom certificate extension carrying some attestation information uses `SET OF` for some parameters. Apple failed to observe the constraints DER-encoded ASN.1 data must fulfil
and did not sort the members of this set as required.
Warden Supreme relies on a lenient ASN.1 parser that does not get tripped by this. If you are processing iOS attestation using other stacks, this could cause issues, though.
