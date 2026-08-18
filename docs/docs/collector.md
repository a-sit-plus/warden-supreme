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

!!! warning "Public Testing Only"
    **The Attestation Collector app and this public service are completely separate from applications and services that
    integrate Warden Supreme.** Integrating Warden Supreme does not register with, connect to, or transmit data to this
    service. The service receives data only when someone deliberately submits an attestation using the Attestation
    Collector app.

    **Never configure a production deployment to send attestations to this service.** This is a public testing endpoint:
    submitted attestation data and diagnostic artefacts may be stored and published.

## Exploring Failure Conditions with Custom Builds

You can build or deliberately modify the Attestation Collector app and submit attestations to the public service. The
attestation can be created and uploaded, but online verification is expected to fail because locally built APKs are not
signed with the certificate trusted for the official Collector release.

This makes custom builds useful for exploring client behaviour and error conditions. After submitting:

1. Download the resulting `debug-statement.json` from the public table.
2. Replace the expected `signerFingerprints` in its recorded Android verification configuration with the fingerprint of
   your locally signed APK.
3. Replay the modified debug statement locally as described in
   [Debugging, Recording, and Replaying Attestation Checks](integration/debugging.md).

Changing `signerFingerprints` modifies only the recorded verification configuration; it does not alter or forge the
attestation evidence. If the package name remains `at.asitplus.warden.collector`, replacing the signer fingerprint lets
the replay proceed beyond the otherwise unavoidable signer mismatch and expose the deliberately triggered error. If you
also change the application ID, update the recorded package-name configuration before replaying.

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

!!! warning "Public Diagnostic Data"
    Submitted attestation details and downloadable diagnostic artefacts appear in the collector's public table. Use it
    only with a device whose attestation information you are comfortable sharing publicly.
