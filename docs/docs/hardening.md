# Security Policy and Hardening

This page provides an overview of Warden Supreme's official security policy, how we handle reports, and how we have
hardened Warden Supreme against attacks.

## Security Policy

Please do **not** report security issues **publicly**. Attackers might use such information to exploit
vulnerabilities before a fix can be developed and deployed.

Instead, please use GitHub's [**private vulnerability reporting**](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/privately-reporting-a-security-vulnerability):

---

![GitHub's "Report a vulnerability" button](https://github.com/user-attachments/assets/ab4a2c05-6948-498b-9a1d-01fe162a0b1e){ style="width: 100%; height: auto;" loading=lazy }

---

- Navigate to the repository's *Security and quality* section on GitHub.
- Click *Report a vulnerability*.
- Follow the private vulnerability reporting flow.

**Please include:**

- A description of the issue.
- Affected versions, commits, or components.
- Reproduction steps or a proof of concept, as far as possible.
- The impact and any suggested mitigation.

**We will:**

- Acknowledge reports promptly.
- Assess severity and impact.
- Work on a fix or mitigation.
- Coordinate disclosure responsibly.

Response and remediation times may vary depending on report complexity, maintainer availability, and release timing.


## Hardening

We believe in transparency. Therefore, we document flaws discovered in released versions, what we did to address them,
and how long it took for fixes to reach a release.

- Some discoveries also affected third-party libraries. We reported them upstream and coordinated releases to avoid
  cross-project exposure.
- Others affected only Warden Supreme; their remediation timelines were entirely our responsibility.

!!! tip inline end "Primary Advisory Source"
    [GitHub](https://github.com/a-sit-plus/warden-supreme/security/advisories) is the primary advisory source and may be
    updated a few hours before this page.

We update this section as new discoveries are made. Always consult the latest published documentation for an up-to-date
overview.

### Warden Supreme 1.1.0

Released on **2026-08-14**.

| State     | Advisory                                                                                                    | Short description                                                                                                                               |   Reported |   Assessed | Resolution |
|-----------|-------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|-----------:|-----------:|------------|
| Published | [GHSA-6jpm-5g92-cpcg](https://github.com/a-sit-plus/warden-supreme/security/advisories/GHSA-6jpm-5g92-cpcg) | Rejects duplicate CSR attributes and extensions. Strictly defence-in-depth, as Warden Supreme delegates semantic CSR validation to integrators. | 2026-08-02 | 2026-08-02 | 2026-08-14 |


### Warden Supreme 1.0.3

Released on **2026-08-12**.

| Advisory                                                                                                    | Short description                                                                                                                                                      |   Reported |   Assessed |   Patched/released |
|-------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------:|-----------:|-------------------:|
| [GHSA-4r28-jj7j-g7v8](https://github.com/a-sit-plus/warden-supreme/security/advisories/GHSA-4r28-jj7j-g7v8) | Limits and canonicalises attacker-controlled Android application IDs and signer digests, and verifies certificate chains before fully decoding attestation extensions. | 2026-08-05 | 2026-08-07 | 2026-08-12 (1.0.3) |
| [GHSA-3chr-q239-rmpp](https://github.com/a-sit-plus/warden-supreme/security/advisories/GHSA-3chr-q239-rmpp) | Replaces full-cache expiry scans with nonce- and expiry-ordered indexes to prevent quadratic CPU denial of service.                                                    | 2026-08-05 | 2026-08-07 | 2026-08-12 (1.0.3) |
| [GHSA-qv7m-wr3r-hfg3](https://github.com/a-sit-plus/warden-supreme/security/advisories/GHSA-qv7m-wr3r-hfg3) | Adds payload-size and nesting guards to prevent verifier stack exhaustion during hybrid JSON deserialisation.                                                          | 2026-08-05 | 2026-08-07 | 2026-08-12 (1.0.3) |
| [GHSA-3qj3-8wvm-fmcp](https://github.com/a-sit-plus/warden-supreme/security/advisories/GHSA-3qj3-8wvm-fmcp) | Bounds nested challenge payload deserialisation to prevent a malicious challenge endpoint from crashing clients.                                                       | 2026-08-05 | 2026-08-05 | 2026-08-12 (1.0.3) |
| [GHSA-744h-w68v-qfpc](https://github.com/a-sit-plus/warden-supreme/security/advisories/GHSA-744h-w68v-qfpc) | Clarifies the verifier's hardware/software OR semantics so operators do not accidentally weaken their attestation policy.                                              | 2026-08-05 | 2026-08-05 | 2026-08-12 (1.0.3) |
| [GHSA-rxrw-2p38-wfmr](https://github.com/a-sit-plus/warden-supreme/security/advisories/GHSA-rxrw-2p38-wfmr) | Safely returns repeated singleton tags when their values agree and reports conflicting values as failures.                                                             | 2026-08-05 | 2026-08-09 | 2026-08-12 (1.0.3) |
| [GHSA-2f9g-97q5-f2wr](https://github.com/a-sit-plus/warden-supreme/security/advisories/GHSA-2f9g-97q5-f2wr) | Includes the App Attest environment in iOS policy selection, preventing sandbox and production policies from being confused.                                           | 2026-08-05 | 2026-08-07 | 2026-08-12 (1.0.3) |

### Warden Supreme 1.0.2

Released on **2026-07-15**.

| Advisory                                                                                                    | Short description                                                                                                                                                              |   Reported |   Assessed |   Patched/released |
|-------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------:|-----------:|-------------------:|
| [GHSA-frpv-cj76-xm4r](https://github.com/a-sit-plus/warden-supreme/security/advisories/GHSA-frpv-cj76-xm4r) | Derives the attestation security level from the certificate chain and requires it to match the level claimed by the attestation extension, preventing StrongBox impersonation. | 2026-07-06 | 2026-07-06 | 2026-07-15 (1.0.2) |

### Warden Supreme 1.0.1

Released on **2026-06-24**. Warden Supreme itself had no published advisory
for this release; it updated Signum to the version containing the upstream fix below.

| Advisory                                                                                                   | Short description                                                                                               |   Reported |   Assessed |   Patched/released |
|------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|-----------:|-----------:|-------------------:|
| [Signum GHSA-hch5-9pjg-jqjh](https://github.com/a-sit-plus/signum/security/advisories/GHSA-hch5-9pjg-jqjh) | Updates to Signum 3.24.0, which bounds recursive ASN.1 operations that could otherwise cause denial of service. | 2026-06-22 | 2026-06-24 | 2026-06-24 (1.0.1) |