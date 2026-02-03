# Leaked Keyboxes

Some Android device manufacturers have, at times, failed to adequately protect private keys used to sign *attestation
certificates*. When such keys leak, they can be copied and reused to produce attestation statements that appear
authentic unless your verifier performs revocation checks.

!!! info "What is a “keybox”?"
    A *keybox* is OEM provisioning material for Android Keystore/Keymaster/KeyMint that includes attestation
    key(s) and certificate chain(s). The name comes from the historical `keybox.xml` packaging used by provisioning
    tools and older devices. When people talk about “leaked keyboxes”, they usually mean this kind of packaged
    attestation key material escaping the secure manufacturing/provisioning process.
    In practice, keyboxes are often file-based provisioning blobs that a device imports into its secure hardware.

To mitigate leaked attestation keys, Google publishes revocation information for Android attestation, and verifiers are expected to reject attestations based on revoked keys (see Android’s
[hardware-backed key attestation documentation]({{ links.android_key_attestation }})).
Warden Supreme incorporates such a check by default.


!!! tip inline end
    If you are concerned about how this affects your service in particular, check out our [&nbsp;💎&nbsp;Services](../../services.md).

This page summarises the resulting security implications and highlights what service operators should consider. In most
deployments, **compromising attestation through leaked keyboxes will have surprisingly little security impact**;
the primary impact is on *services* that use attestation as an integrity gate.
In the end, whether leaked keyboxes pose a real-world threat must be evaluated on a **case-by-case basis**.

## Background

This section explains how keyboxes fit into Android attestation key provisioning, and why certain provisioning choices
can turn filesystem leaks into reusable attestation keys. It also highlights why revocation is the practical control that
service operators can reliably enforce, regardless of how a given OEM implemented provisioning.



### Historical Attestation Key Provisioning

Android’s security model expects attestation signing keys to be protected by secure hardware and used *inside* that secure
environment (see
[Key and ID Attestation]({{ links.android_key_id_attestation }})).
At the same time, attestation signing keys **must be shared across a sufficiently large population** to avoid becoming
de-facto device identifiers (privacy requirement). The Android CDD discusses this privacy-driven “shared key” model (for
example Android 14:
[Android 14 CDD]({{ links.android_14_cdd }})).

#### Blast Radius of Leaked Keyboxes

Because keys are intentionally shared, a *single* compromised attestation signing key can affect **an entire manufacturing batch / SKU slice**. In practice this means:

- If a shared key is revoked, **many otherwise legitimate devices** that rely on that key will fail revocation checks.
- The “blast radius” is not one device — it is potentially the entire cohort that shares the key.

#### Revocation Mechanism

Google publishes revocation information as an **attestation status list** that is regularly updated. The list is
publicly retrievable (JSON) and contains the serial number of many certificates whose corresponding private keys were
leaked. Entries include revocation status and reason (for example, `KEY_COMPROMISE`). See
[Verify Hardware‑Backed Key Pairs with Key Attestation]({{ links.android_key_attestation }}).

#### On Leaked `keybox.xml` Material

Community reports and tooling around `keybox.xml` describe how plaintext key material can be copied and reused if it
becomes accessible (for example via filesystem extraction on vulnerable devices). Treat such reports as *threat
intelligence*, not as authoritative platform guarantees.

### Encrypted vs Plaintext Keyboxes (Why Leaks Happen at All)

For **GMS-certified** devices, private keys used for attestation are required to be protected by secure hardware and not
be extractable (see
[Android device certification / compatibility]({{ links.android_compat_overview }})).

Historically, many OEMs implemented this with file-based provisioning:

- Per-device provisioning material is stored on the device filesystem in **encrypted / wrapped** form.
- The device’s secure hardware can **unwrap/decrypt** it and import it into the hardware-backed keystore.
- The resulting security level is comparable to “keys injected directly into hardware”, because a copied provisioning
  file is useless without the specific target device it was provisioned for.

_So how do “leaked keyboxes” show up in the first place?_

- AOSP reference/provisioning code and vendor test tooling commonly include **test modes** that allow importing
  **plaintext** private keys for development and bring-up.
- If an OEM (or a supplier in the provisioning chain) uses such plaintext keyboxes outside strictly controlled testing,
  the provisioning blob can be extracted and duplicated. Duplicates can then be imported on other devices, producing
  attestations that look valid until the corresponding attestation key is revoked.
- Google’s certification requirements forbid using plaintext keybox key material on production devices; however, fully
  automated certification checks for this are not practical in general, so compliance is partly ensured by OEM
  attestation and audits.

### Remote Key Provisioning (RKP)

Android has been moving away from long-lived, factory-provisioned attestation keys towards **Remote Key Provisioning (RKP)** to
tackle the issue of leaked keys:

- Android **12** introduced RKP; Android **15** requires devices to implement it (see
  [Remote Key Provisioning]({{ links.android_rkp_source }})).
- RKP replaces in-factory private key provisioning with a model that uses in-factory public key material and
  **over-the-air provisioning of short-lived certificates**.
- In AOSP, RKP is implemented with a dedicated stack; newer Android versions package parts of it as a **Mainline module**
  (`com.android.rkpd`, the `rkpd` daemon) to improve updateability (see
  [Remote Key Provisioning]({{ links.android_rkp_source }})).

**Security consequence (relevant to leaked keyboxes)**

RKP reduces the value of “static” leaked provisioning artefacts because it shifts attestation certificate issuance towards
a fresher, online-managed model with improved recoverability.  
See also:
[Remote Key Provisioning]({{ links.android_rkp_source }}) and
[platform quirks around RKP](../quirks.md#remote-provisioning).

For a deeper (and sometimes market-adjacent) perspective on how leaked key material is obtained, traded, and detected,
community analysis can provide useful context (for example
[Android Keybox Attestation Analysis]({{ links.tryigit_keybox_analysis }})). Treat these sources as threat
intelligence and anecdotal reporting, not as authoritative platform guarantees.



## Security Implications

Leaked keyboxes are best understood as a *reliability* problem for attestation-based gating: they can let some devices
produce attestations that look valid, until revocation catches up. The actual impact depends on the attacker’s ability to
control the device environment and manage key reuse.

### Who Benefits from Leaked Key Material?

There are typically three groups with interest in bypassing attestation-based checks:

1. **Opportunistic attackers (large-scale campaigns)** aim to distribute malware broadly (for example, trojanised banking
   apps to defraud users). Leaked keys are a poor fit here:  
   Attackers would need a steady supply of not-yet-revoked keys,
   avoid reusing keys to delay detection, and maintain extra infrastructure to route app-side attestation calls through
   the stolen key material. The cost and operational risk often compares unfavourably to cheaper, scalable alternatives
   like phishing and social engineering.
2. **Users tinkering with their own device** (custom ROMs, root, instrumentation) may use leaked key material to make a
   modified device pass an attestation gate without investing in a full exploit chain.
3. **Targeted attackers (high-touch compromise)** may treat leaked keys as one ingredient in a broader operation, but
   attestation was never meant to single-handedly stop a determined adversary with the capability to compromise devices.

!!! info "Key Takeaway"
    Leaked attestation keys are *not* a universal bypass for everyone. They matter most where the attacker controls the
    device or environment and can carefully manage reuse; they are much less suitable for broad, scalable campaigns.

### Revocation Is Essential — and Has Trade-Offs

Because key sharing is a privacy requirement, revoking a compromised key can imply collateral impact:

- **Revoking one key may disable attestation acceptance for a large device cohort** sharing that key.
- Not revoking keeps the ecosystem exposed.

This is exactly why Google treats revocation as a first-class part of the attestation trust model and publishes a status
list for verifiers. In practice, Google also monitors signals of compromised/leaked attestation keys, assesses expected
blast radius, and updates the published revocation data accordingly (often rapidly once a key starts being reused at
scale).

### Black Market Reality (Operational Expectation)

Leaked/plaintext keybox material is widely discussed in the Android modding ecosystem, including marketplaces for
“working keyboxes”.

Operationally, two patterns matter for threat modelling:

- Traded plaintext keyboxes frequently get revoked quickly once they become visible at scale; community reports suggest
  “days to a couple of weeks” is common.
- Many offers are therefore effectively a scam (a keybox that is already revoked, or will be revoked shortly after
  purchase). Some sellers advertise “VIP” keyboxes that supposedly stay valid for months/years; treat such claims with
  skepticism unless you have independent evidence.

!!! warning "Not Every Non‑RKP Key Can Be Leaked"
    Some community write-ups argue (implicitly or explicitly) that *any* device not using RKP should be assumed to have
    leakable attestation keys. That conclusion is often overly pessimistic:
    
    - It conflates “not RKP” with “plaintext provisioning” or “extractable private keys”. Many pre-RKP devices still use
      secure-hardware-backed attestation keys provisioned in ways that are not practically reusable off-device (e.g., wrapped
      per-device material as described above).
    - It treats OEM or supply-chain failures as inevitable. Leakage does happen, but it is not a given for every **GMS-certified**
      device generation.
    - It overlooks attacker economics: stealing and operationalising key material at scale is costly, and revocation reduces
      the window of usefulness.
    
    The actionable interpretation for verifiers is simpler and less speculative: treat non-RKP attestation as *more exposed
    to long-lived key reuse and provisioning mistakes*, and require revocation checks. For higher assurance tiers, it can be
    reasonable to prefer or require RKP (see
    [Android Attestation Deep Dive](../android.md#server-side-verification-checklist) and
    [Threat Models](../../bg/threatmodels.md)).



## What Service Operators Should Do

From an operator perspective, the goal is not to “detect keyboxes” directly, but to make attestation decisions resilient
against compromised provisioning material. That typically means treating Google’s revocation feeds as mandatory input,
and layering policy constraints (including, where appropriate, RKP preference/requirements) to match your service’s
assurance needs.

### Minimum Recommended Controls

The canonical checklist lives in the [Android Attestation Deep Dive](../android.md#server-side-verification-checklist).
For convenience, the minimum set relevant to leaked keyboxes is summarised here:

- Full chain validation
- Anchoring in Google’s attestation roots
- Fresh challenge binding
- Boot state policy checks
- App identity binding (package + signer digests)
- **Revocation checks against Google feeds**
- (Optionally) additional revocation lists for higher assurance contexts

### When Additional Revocation Lists Make Sense

Even if you already consume Google’s official status list, operational reality can require **supplemental** controls, for example:

- You ingest *your own* monitoring / incident response intelligence.
- You want environment-specific hardening (e.g., stricter policies for a regulated service tier).
- You need deterministic change control (e.g., staged rollout, extra audit trails, or “hotfix” deny entries during an incident).

Warden Supreme explicitly supports checking “Google feeds and your own revocation lists” in the Android verification pipeline.
For configuration details, see
[Flexible Android Revocation Configuration](../../integration/supreme.md#flexible-android-revocation-configuration).


## References

- [Android hardware-backed key attestation (incl. revocation list semantics)]({{ links.android_key_attestation }})
- [AOSP: Key and ID Attestation]({{ links.android_key_id_attestation }})
- [AOSP: Remote Key Provisioning]({{ links.android_rkp_source }})
- [Android device certification / compatibility overview]({{ links.android_compat_overview }})
- [Android 14 CDD]({{ links.android_14_cdd }})
- [Warden Supreme checklist (revocation + revocation lists)](../android.md#server-side-verification-checklist)
- [Warden Supreme changelog](../../CHANGELOG.md)
- [Community analysis: Android keybox attestation]({{ links.tryigit_keybox_analysis }})
- [Community example: “VIP keybox” marketing]({{ links.tryigit_keybox_vip }})
