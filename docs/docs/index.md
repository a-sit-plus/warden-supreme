
![Warden Supreme](assets/images/warden-supreme.png){ .img-center }

# Your One‑Stop Shop for Mobile Client Attestation { .img-center }

Warden Supreme is a comprehensive solution for remote attestation on mobile platforms.
It provides a unified framework to verify the integrity of Android and iOS client applications and the devices the are running on,
ensuring that only authentic, untampered apps can access a service. This project consolidates
[WARDEN](https://github.com/a-sit-plus/warden) and [WARDEN‑roboto](https://github.com/a-sit-plus/warden-roboto),
integrating them with [Signum](https://a-sit-plus.github.io/signum/), a Kotlin Multiplatform crypto/PKI library,
to deliver a streamlined attestation format and developer experience.

!!! tip
    Already familiar with attestation? **[Jump to the Integration Guide](integration/supreme.md)**.

This documentation goes beyond Warden Supreme specifics and provides a structured overview of remote attestation,
from concepts to hands‑on integration:

* **Background**
    * What is Remote Attestation? A security mechanism where a device proves its integrity to a remote server by producing a signed statement about its hardware, OS state, and app identity.  
      → See [Remote Attestation Primer](bg/primer.md).
    * Why attestation beats heuristics (e.g., simple “root checks”), plus threat models and risks.  
      → See [Threat Models and Risks](bg/threatmodels.md).
    * “Pure” Attestation vs. proprietary services (Google Play Integrity, Apple App Attest), privacy, data protection, and digital sovereignty.  
      → See [Privacy and Data Protection](bg/privacy.md).

* **Technical Details**
    * Android key attestation: proving hardware‑backed keys and embedding app identity in the attestation record.  
      → See [Technical Deep Dive: Android](technical/android.md).
    * iOS App Attest: verifying app integrity and emulating key attestation semantics.  
      → See [Technical Deep Dive: iOS](technical/ios.md).
    * Pitfalls, quirks, and workarounds requiring careful evaluation.  
      → See [Technical Deep Dive: Quirks and Hints](technical/quirks.md).

* **Integrating Warden Supreme**  
  Warden Supreme includes the battle‑tested, formerly stand‑alone WARDEN library that has attested millions of devices in production.
  Using Warden Supreme reduces integration pitfalls and complexity, enabling you to:
    - ✅ Verify device and app integrity using hardware‑backed proofs
    - ✅ Support Android Key Attestation (see [Android Key & ID Attestation](https://source.android.com/docs/security/features/keystore/attestation))
    - ✅ Support Apple App Attest (see [DeviceCheck / App Attest](https://developer.apple.com/documentation/devicecheck)) with key attestation emulation
    - ✅ Use a unified server API for both platforms
    - ✅ Use a unified client API for both platforms

<span style="margin-left: 1.85em">→ See the [Integration Guide](integration/supreme.md).</span>
  
* **Glossary**  
  A comprehensive glossary covering terminology across the attestation domain.  
  → See the [Glossary](glossary.md).


!!! info "Help Wanted"
    This living document aims to be an authoritative resource on attestation.
    If something is incorrect or missing, please [file an issue](https://github.com/a-sit-plus/warden-supreme/issues/new).

---
<p align="center">
This project has received funding from the European Union’s Horizon 2020 research and innovation
programme under grant agreement No 959072.
</p>
<p align="center">
<img src="assets/images/eu.svg" alt="EU flag">
</p>
