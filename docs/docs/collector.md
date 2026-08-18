# Attestation Collector

The Attestation Collector lets you produce and inspect Android Key Attestation on
a real device without integrating Warden Supreme into your own app or service. The result includes the attested
security level, Android and patch version, verified-boot state, application identity, certificate chain, and the parsed
attestation extension.

<div class="collector-launch">
  <figure>
  <a class="md-button md-button--primary" href="{{ links.attestation_collector }}">Open the<br>Attestation<br>Collector</a>
  <figcaption>Click to see collected attestations</figcaption>
  </figure>
  <figure>
    <a href="{{ links.attestation_collector }}/collector.apk">
      <img src="../assets/images/collector-apk-qr.svg" alt="QR code linking directly to the Attestation Collector APK">
    </a>
    <figcaption>Click or scan to download the APK</figcaption>
  </figure>
</div>

## Using the Collector

1. Open the collector and download the Android APK.
2. Install the APK on the device you want to examine.
3. Keep the preconfigured backend domain and select **Attest**.
4. Inspect the result in the app or the collected-attestations table in your browser.

The collector creates a fresh attested key and evaluates its proof with Warden Supreme. Successful and failed results
are both useful: the parsed statement shows what the device produced, while the verification result shows whether it
met the policy.

## Interpreting Results

The public collector deliberately uses Warden Supreme's Android defaults, except for already using our home-grown 
attestation extension parser. A successful result therefore requires:

- hardware-backed attestation
- a locked bootloader
- vendor-managed OEM verified boot
- a chain anchored in the default Google hardware-attestation roots

**The result describes this collector policy, not every valid attestation policy!** For example, Warden Supreme can be
configured to trust selected hardened custom-ROM boot keys, such as GrapheneOS but the public collector does not do so. Patch-level,
minimum Android-version, StrongBox, and application-specific production requirements also depend on the policy of the
service performing verification. The default configuration is very generic/lax in this regard.

!!! warning "Public Diagnostic Service"
    Submitted attestation details and downloadable diagnostic artefacts appear in the collector's public table. Use it
    only with a device whose attestation information you are comfortable sharing publicly. Do not treat the service as
    a production enrolment endpoint.  
    **No personally identifying data is shared!**
