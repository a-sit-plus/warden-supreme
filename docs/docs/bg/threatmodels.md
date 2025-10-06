# Threat Models and Risks

Attestation is not a panacea—nothing ever is.
Attestation is, however, a powerful mechanism that significantly raises the security bar for clients that would
otherwise be untrusted.  
This page outlines common threats and how attestation helps mitigate them, with practical, easy‑to‑apply policies.

## Threat Model A — Everyday Tampering and Rooted Devices

This scenario covers mainstream, widely available tampering done at scale using off‑the‑shelf tools and tutorials:

- Rooting
- Unlocking the bootloader
- Repackaging an app (modifying an APK/IPA, injecting code, or resigning with a different key)

Attackers here are opportunistic. They apply whatever guide or exploit is currently popular to a stock phone and try to
use your service.

To keep such devices and apps out, require strong, cryptographic platform guarantees:

- Android  
  - Accept only attestation records with `verifiedBootState: Verified` and a locked bootloader.  
  - Enforce a minimum OS security patch level to exclude known, widely exploited vulnerabilities.  
  - Verify the app identity: compare package name and signing‑certificate digest(s) against your allowlist.

- iOS  
  - Require a complete App Attest certificate chain, validate the challenge/nonce, and ensure the device counter
  increases monotonically.

Since software‑only Android attestation can be forged on rooted devices, the policy decision is simple:  
**Accept hardware‑backed attestation only; reject software attestation.** This preserves access for honest users while
filtering out cheap, commoditized attacks.

!!! example "Example Repackaging Attacks"
    Attestation thwarts common repackaging patterns such as:

    - Modifying network calls to bypass server‑side checks and resigning the app with an attacker key.
    - Injecting ad‑fraud or click‑spam SDKs into a popular app to monetize traffic.
    - Stripping certificate pinning hooks and shipping a “patched” build to enable man-in-the-middle attacks.
    - Inject malicious code to exfiltrate sensitive data.
    
    In each case, the app identity (package name + signer digest) and the hardware‑backed attestation prevent a repackaged or resigned app from being accepted.

### Concrete Example: Repackaging ID Austria

Public demonstrations have shown attempts to repackage apps to bypass client‑side checks (e.g., root/jailbreak
detection, pinning) and then re‑sign the modified APK with a different key. A documented community example is
[github.com/eGovPatchesAT/id-austria](https://github.com/eGovPatchesAT/id-austria),
which explores patching attempts against the Austrian _Digitales Amt_ app.

**What the repository proposes and why it’s relevant:**

- It documents techniques commonly discussed in reverse‑engineering communities: extracting the APK, modifying bytecode
  or hooks to disable checks (e.g., root detection, SSL pinning), rebuilding, and re‑signing with a non‑official key.
- It showcases that client‑side defenses alone (root checks, anti‑debug, obfuscation) can be removed or bypassed once an
  attacker controls the binary, reinforcing the need for server‑side verification based on cryptography rather than
  heuristics.
- It serves as a real‑world illustration that repackaging is mechanically feasible but strategically futile against
  services that enforce hardware‑backed attestation and app‑identity binding.

**Why this fails under proper attestation:**

- App identity binding (Android): The attestation record includes the package name and signing‑certificate digest(s).
  Any repackaged build must be signed with a different key; its signer digest won’t match the backend allowlist and is
  rejected.
- Hardware root of trust: Attestation is produced by secure hardware (TEE/StrongBox), which cannot be forged by a
  modified client. Software‑only attestations are rejected by policy.
- Freshness binding: The server‑issued challenge/nonce is bound into the attestation, preventing replay of genuine
  statements from other devices or app instances.
- Platform integrity gates: Requiring Verified Boot and a locked bootloader, plus enforcing current OS/security patch
  levels, further blocks devices where low‑level hooks or instrumentation would typically be installed.

!!! tip "Takeaway"
    Even if client‑side protections (e.g., root checks) are patched out, a backend enforcing hardware‑backed
    attestation with an app‑identity allowlist rejects repackaged apps by construction.

## Threat Model B — Bot Farms, Sybil Attacks, and Large‑Scale Emulator Abuse

Here the adversary doesn’t necessarily tamper with the OS. Instead, they spin up thousands of virtual devices (a form of
a [Sybil attack](http://research.microsoft.com/en-us/um/people/douceur/documents/sybil.pdf)—many forged identities controlled by one adversary)
or automate UI flows on “farms” of cheap handsets to commit large‑scale fraud (e.g., credential stuffing, promo abuse, ad‑click inflation).

Emulators are effectively free to scale—marginal costs are primarily CPU time and cloud instances
(see [Google Cloud — VM Instance Pricing](https://cloud.google.com/compute/vm-instance-pricing))—which makes them attractive
for abuse at massive volume. The Android Emulator’s headless/CI mode also makes horizontal scaling trivial via scripts and
containers (see [Android Emulator — Command‑Line and Headless Usage](https://developer.android.com/studio/run/emulator-commandline)).
In addition, bot operators often modify or instrument Android builds on physical devices to ease automation (e.g.,
[abusing Accessibility Services](https://iamjosephmj.medium.com/unveiling-accessibility-attacks-on-android-code-examples-and-countermeasures-de16bd25c76c),
engineering/rooting ROMs, or repackaging apps to expose hooks and bypass certificate
pinning).

Defense therefore focuses on distinguishing real, unique devices and making horizontal scaling expensive, while selectively excluding low‑cost hardware classes:

- **Attestation requirements:**
    - Demand hardware‑backed attestation. For sensitive workflows on known device fleets, consider requiring StrongBox on Android 9+ if your user base supports it (this excludes most budget and many older devices).
    - Reject emulator attestation roots and uncertified build fingerprints.
    - Verify app identity against your allowlist (package name + signing‑certificate digest).
- **Cost‑increasing policy levers** (apply based on audience support):
    - Minimum Android OS version: Set a recent floor to exclude older, cheaper second‑hand devices that dominate farms.  
    - Patch‑level floor: Require recent security patch levels to filter out poorly maintained devices.  
    - Device capabilities: Prefer StrongBox when feasible to rule out inexpensive hardware.
    - Integrity signals: Combine attestation with server‑side anomaly detection (rate limits, IP reputation, proof‑of‑work for abuse endpoints) to degrade automation ROI.

!!! warning inline end
    Consider your target audience! If you target a wide user base, you cannot demand fully updated, top-of-the-line devices.

The goal is to ensure real hardware, block modified apps, and systematically remove the cheapest device classes from
eligibility. Even the simple fact of requiring real hardware raises the cost of Sybil attacks astronomically compared to using emulators.
Enforcing modern hardware with up‑to‑date security greatly increases the
operating cost of a bot farm and reduces feasibility of such operations.

## Threat Model C — Targeted Attackers with Physical Device Access

!!! warning inline end
    Attestation cannot detect unknown (zero‑day) or kernel‑level root exploits!

Consider a well‑funded adversary who can access a user’s device and invest in custom exploits, downgrades, or supply‑chain manipulation (e.g., high‑value account takeover, corporate espionage).
Attestation cannot detect unknown (zero‑day) or kernel‑level root exploits, so perfect prevention is unrealistic.
However, you can raise the cost and reduce exposure—primarily on Android, where policies are explicit and verifiable:

- **Rollback Resistance**
    - Accept only attestation statements asserting rollback resistance to block silent firmware or key downgrades.
- **Dedicated Secure Hardware**
    - Require StrongBox‑backed Keystore for the highest level of hardware isolation.
- **Enforce Latest Security Updates**
    - Keep policies strict and current: allow only recent OS versions with up‑to‑date security patches.
- **User Presence / Authentication**
    - Tie sensitive operations (e.g., transaction signing) to fresh biometric authentication so keys cannot be used without the legitimate user.

These controls will exclude older or lower‑end devices. The policy trade‑off is explicit: choose assurance over coverage when stakes are high!

!!! example "Choosing a Policy That Matches Your Risk"
    - Low to moderate risk:
        - Hardware attestation
        - Locked bootloader + verified boot (possibly allowing known-good custom ROM verified boot keys)
        - Reject older patch‑levels
    - Hardening against targeted attacks:
        - Require StrongBox
        - Rollback resistance
        - Require latest patch levels + app version
        - Require latest and greatest OS version