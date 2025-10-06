# Data Protection and Privacy in Mobile Attestation

This page discusses privacy and data protection aspects of attestation.
It outlines "pure" Android hardware attestation, iOS App Attest, and Google Play
Integrity.  
It explains

* what each mechanism is
* the exact data flows (who learns what)
* where policies live
* implications for custom ROMs
* availability and operational trade-offs
* how to combine these approaches in privacy-respecting deployments

## Different Attestation Approaches = Different Privacy Postures

Mobile attestation systems fall into two categories:

* **Evidence-based** attestation returns cryptographic statements you verify yourself. This favors data minimization,
  explainability, and local policy control because your backend decides based on attested fields rather than third-party
  verdicts.
* **Verdict-based** services return labels (for example, “meets device integrity”) computed by a provider from telemetry you
  send them. This is convenient for anti-abuse but introduces per-request data flows to that provider, couples access
  decisions to their definitions, and adds dependency on their availability and quotas.

Across all options, three privacy levers matter most:

1. Per-request third-party contact (is a provider in the hot path?)
2. Policy ownership (do you define acceptance criteria locally?)
3. Firmware trust roots (can you accept your custom/sovereign ROMs?)

## "Pure" Android Attestation (Hardware Attestation You Verify)

A cryptographic hardware module on Android devices generates a key pair and returns an X.509 certificate chain whose
leaf carries the
Android attestation extension. This extension encodes, among other fields:

* Verified Boot state (for example, `VERIFIED` or `SELF_SIGNED`) and bootloader lock state
* OS version and security patch level (used for minimum-version policies)
* App identity binding (package name and signing certificate digest)
* Key properties (algorithm and size, purpose, digests, key origin TEE/StrongBox, user-auth requirements such as user
  presence or auth-per-use)
* A server-provided challenge to guarantee freshness and prevent replay

Your server validates the chain to recognized Android attestation roots, parses the extension, and evaluates your
acceptance policy. The policy can be strict (e.g., require StrongBox, recent patch levels)
or flexible (e.g., allow some legacy devices and don't require strict app integrity), but the decision is yours and is explainable from attested
fields.

### Data Flow (Who Learns What)

| From         | To                                   | Data / Action                                                                                                                                                          |
|--------------|--------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| App          | Your backend  (per&nbsp;attestation) | Attestation certificate chain (leaf, intermediates, root), echoed challenge, app binding, boot- and patch-level claims, key metadata                                   |
| Your backend | Google servers (periodic)            | Download revocation lists and cache them privately. No per-request contact with Google occurs during verification. |

!!! info "Privacy posture"
    Per-request device and app details flow only between your client and your server. Google does not **observe individual
    attestation events.**

### Policy and Governance

Because verification and policy live on your backend, you define and transparently enforce:

* Boot integrity: require verified boot and a locked bootloader
* Minimum platform state: reject OS versions or patch levels below a floor you set (for example, year-month)
* Hardware quality: optionally require StrongBox where available; optionally record TEE versus StrongBox origin
* App identity: specify allows package name(s) and signing certificate digest(s); optionally enforce minimum app version
  code
* User-auth semantics: require user presence/authorization for key use where appropriate (for example, high-risk
  actions)

### Custom Firmware and Sovereignty

You can accept your organization’s verified-boot (AVB) root(s) and thus trust sovereign
or enterprise ROMs, provided verified boot is on and the device is locked. This cannot be expressed in Google Play
Integrity’s official verdicts.

### Key Lifecycle and User-Auth Privacy Nuances

* Keys configured to require user authentication provide user-presence or authorization guarantees at use time without
  sending personal data to third parties.
* Local state changes can permanently invalidate keys: disabling or resetting the secure lock screen; biometric
  enrollment changes when keys are configured to invalidate on enrollment; unlocking the bootloader (which typically
  wipes
  keys and flips verified-boot state). These are enforced by the device and do not require external telemetry.
* When keys are invalidated by policy, subsequent operations bound to the key, such as signatures, fail, and your server
  can prompt the client
  to re-establish trust under the updated state.

## iOS App Attest (Apple-Hosted Attestation and Assertions)

App Attest allows an app to create a Secure Enclave key and obtain an Apple-signed attestation proving that a legitimate
instance of your app (Team ID and Bundle ID) on that device created it. The server validates Apple’s signatures and
checks:

* App identity (team and bundle), challenge binding, and attestation or assertion counters
* Freshness via server-issued nonces and monotonic counters that must increase in valid sequences
* (Optionally:) Ongoing use via assertions that bind new server challenges to the established app instance

Android-like “key attestation” semantics can be emulated by binding the attested app instance to an app-managed key and
having the server verify that binding.

### Data Flow (Who Learns What)

| From | To                                  | Data / Action                                                                                                             |
|------|-------------------------------------|---------------------------------------------------------------------------------------------------------------------------|
| App  | Apple (per&nbsp;attestation)        | Device contacts Apple to obtain or refresh attestation artifacts. Apple learns that an attestation occurred for your app. |
| App  | Your backend (per&nbsp;attestation) | Apple-signed attestation and assertion artifacts are evaluated. No revocation checks towards Apple are needed.            |

!!! info "Privacy posture"
    Apple is in the hot path by design. Your backend still makes the pass/fail decision from signed evidence, but Apple
    learns about each attestation or assertion event.

### Operational Characteristics and Privacy Considerations

* Online requirement: design retry/queuing for temporary network issues and service availability; use Apple’s sandbox
  flag
  during development to keep test events separate from production metrics.
* Policy remains on your backend; the attestation service and its telemetry are Apple-hosted.
* Firmware trust is Apple-controlled; there is no notion of accepting custom firmware trust roots.

## Google Play Integrity (Google-Hosted Verdict Service)

Play Integrity returns opaque tokens that are **interpreted exclusively by Google** and mapped to coarse-grained verdict
labels such as

* Device and integrity tiers (locked boot-loader on OEM-certified firmware; higher tiers additionally demand recent
  patch levels)
* App Integrity (whether Google recognizes the exact APK/IPA that is installed)
* Account or licensing context (ties the verdict to the signed-in Play account)
* Optional environment signals (for example, Play Protect status, screen-overlay risk, device-recall flags)

Your app must go online, obtain a token from Google, and then hand that token to your backend, which can do **nothing
more** than trust the embedded labels and apply hard-coded gating logic.

### Data Flow (Who Learns What)

| From | To                              | Data / Action                                                                                                                                  |
|------|---------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------|
| App  | Google (per&nbsp;request)       | Sends nonce or request-hash inputs, app metadata, device-integrity information, and account/licensing signals so Google can compute a verdict. |
| App  | Your backend (per&nbsp;request) | Passes the resulting token; your backend validates and interprets it, then applies policy.                                                     |

!!! info "Privacy posture"
    Google sees per-request signals each time you evaluate integrity. Avoid including sensitive raw identifiers in nonce
    inputs; hash or encrypt where appropriate, within provider constraints.

### Policy, Custom Firmware, and Governance

* Policy behind labels is Google-defined; you cannot redefine the criteria.
* Custom verified-boot keys and trusted custom ROMs cannot achieve device or strong integrity, even if relocked and
  objectively secure, because certified OEM firmware is required.
* Coupling to Play distribution and licensing can benefit anti-piracy, but it is not privacy-minimal and may conflict
  with sovereignty requirements.

### Operational Characteristics

Relying on Play Integrity means surrendering control over your security policy to a third party whose incentives may not
match yours.  
If your threat model or regulatory environment demands deterministic, auditable evidence, or if you need to accept
sovereign firmware builds, use pure hardware attestation instead of (or in addition to) Google’s
black-box verdict service.

### Why Pure Attestation Gives You Stronger Guarantees

With remote attestation you receive a *cryptographically verifiable* statement that you can parse, audit and store
independently of the platform vendor.  
You decide which boot state, patch level or package signature is acceptable—and you can prove that decision later.

Play Integrity, by contrast, offers **no raw evidence**. Google’s backend hides the actual attestation chain, performs
the
evaluation on its own servers, and sends back a single token that merely says *pass* or *fail* according to **Google’s
undocumented and changeable policy**.  
If Google tightens or loosens its criteria—or simply makes a mistake—you have no recourse and no visibility.

Moreover, the service runs in Google’s hot path **for every request**:

* You inherit Google’s latency, availability, and regional outages.
* Daily quotas and rate limits can throttle your traffic.
* You cannot whitelist secure custom ROMs or enterprise firmware because the verdict hard-codes “OEM certified” as the
  one-size-fits-all requirement.

## Comparative Privacy and Control

| Dimension                        | Android “pure” attestation               | iOS App Attest                                 | Google Play Integrity                         |
|----------------------------------|------------------------------------------|------------------------------------------------|-----------------------------------------------|
| Per-request third-party contact  | None                                     | Apple required                                 | Google required                               |
| Who learns per-request events    | Only you                                 | Apple and you                                  | Google and you                                |
| Return type                      | Evidence (X.509 plus attestation fields) | Evidence (Apple-signed artifacts)              | Verdict (labels or tiers)                     |
| Policy ownership                 | You (field-level rules)                  | You (verify evidence; service is Apple-hosted) | Google (definitions behind labels)            |
| Custom AVB roots or trusted ROMs | Allowed (you can admit your keys)        | Not applicable                                 | Not allowed (OEM-certified firmware required) |
| Distribution coupling            | None                                     | None (service dependency on Apple)             | Tight to Play ecosystem or licensing          |
| Availability and quotas          | Your backend; cacheable roots and CRLs   | Apple in the hot path                          | Google in the hot path; quotas                |
| Data minimization                | Maximal                                  | Moderate                                       | Least                                         |

### Data-Flow Sketches (At a Glance)

| System         | Channel                          | Data / Action                                 |
|----------------|----------------------------------|-----------------------------------------------|
| Android “pure” | App → Your backend               | Hardware-backed attestation evidence          |
|                | Your backend → Android endpoints | Periodic download of public roots and CRLs    |
| iOS App Attest | App ↔ Apple                      | Attestation creation and assertion refresh    |
|                | App → Your backend               | Apple-signed attestation / assertion evidence |
| Play Integrity | App ↔ Google                     | Per-request exchange to obtain a verdict      |
|                | App → Your backend               | Google-signed verdict token                   |

---

## Implementation guidance that preserves privacy

1. Always bind a fresh, single-use server challenge and enforce short freshness windows; never accept attestations with
   mismatched or stale challenges.
2. On Android, verify verified-boot and lock state; set patch-level floors; pin package name(s) and signing certificate
   digest(s). Where governance requires sovereign control,
   admit your own AVB root(s) and verify the attested boot chain accordingly.
3. On iOS, minimize assertion frequency to what your risk posture and UX require; document the online dependency and
   provider metrics; use sandbox in development; queue and retry around transient provider outages.
4. If you must integrate Play Integrity, **beware of the dependencies and privacy implications** treat it as a
   supplementary anti-abuse signal. Budget for quotas and outages; hash or
   encrypt nonce inputs if they might contain sensitive identifiers; do not let provider verdicts replace your
   cryptographic evidence as the root of trust where privacy or sovereignty is required.
5. Keep explainable server-side logs that capture which attested fields passed or failed (boot state, patch level, app
   ID binding, counters) without storing more personal data than necessary.
6. Refresh public revocation lists out of band and cache them; avoid per-request calls to external endpoints
   for verification.
7. For testing and CI, use captured, known-good attestation artifacts and negative cases to exercise parsing, policy
   evaluation, and error reporting; cover edge cases such as timestamp encoding quirks, misencoded patch levels, and
   leaf-certificate validity anomalies on certain vendors.
8. Consider Remote Key Provisioning pool behavior on Android when Google provisioning services may not be available

---

## Practical coexistence patterns

* Evidence-first: make Android “pure” attestation and iOS App Attest your root of trust. This keeps decisions
  explainable and privacy-minimal (Android) while acknowledging iOS’s provider contact.
* Forego Play Integrity, but if you insist, use it only as a second signal for specific flows (for example,
  account recovery), with a narrow scope and explicit documentation of additional data sharing.
* Sovereign builds: if you operate controlled firmware with your own verified-boot keys, use Android “pure” attestation
  to admit those devices; this is incompatible with Play Integrity’s device or strong integrity criteria.

---

## Conclusion

If your priorities include data minimization, explainability, local policy control, and the option to trust devices that
boot images signed under your own verified-boot keys, ground your mobile trust in Android “pure” attestation and
use iOS App Attest (given that there are no alternatives on Apple platforms).
Forego Play Integrity. This keeps per-request telemetry with providers to the minimum required, preserves
governance over acceptance criteria, and yields an auditable, privacy-respecting foundation for secure mobile services.
