# Software Bill of Materials

Warden Supreme publishes CycloneDX SBOMs for every Maven publication of every published module.

Each SBOM describes one published Maven artifact, not just one Gradle project. For Kotlin Multiplatform modules that
means there is usually one SBOM for the root `kotlinMultiplatform` publication and one SBOM for each concrete target
publication such as `jvm`, `android`, `iosArm64`, or `iosSimulatorArm64`.

## Formats

- CycloneDX JSON
- CycloneDX XML

## How To Read The SBOMs

Warden Supreme publishes publication-oriented SBOMs:

- the `kotlinMultiplatform` SBOM is the root metadata publication SBOM
- target SBOMs such as `jvm`, `android`, `iosArm64`, and `iosSimulatorArm64` describe the concrete published target artifacts
- JVM-only publications such as `mavenJava` describe the published JVM artifact for that module

This distinction matters when interpreting dependencies:

- a `kotlinMultiplatform` SBOM can legitimately reference metadata-oriented artifacts used for variant selection
- a target SBOM reflects the concrete artifact a consumer resolves for that platform
- JVM publications such as `mavenJava` reflect the published server-side jar for that module

The most useful rule of thumb is:

- use `kotlinMultiplatform` if you want the root KMP metadata publication view
- use a target SBOM if you want the concrete artifact a consumer resolves for that platform
- use `mavenJava` for the published JVM server-side modules

## Maven Central

Each published Warden Supreme Maven publication attaches its SBOM with the standard `cyclonedx` classifier:

- `artifact-version-cyclonedx.json`
- `artifact-version-cyclonedx.xml`

For a multiplatform module, that means one SBOM pair for each publication such as `kotlinMultiplatform`, `jvm`,
`android`, `iosArm64`, and so on is created and published.

On Maven Central, look for the normal publication artifact first and then the attached SBOM files with classifier
`cyclonedx`.

## Documentation Downloads

The documentation site mirrors the publication layout used for publishing and exposes the same per-publication SBOM
files:

- `sbom/publications/<module>/<publication>/bom.json`
- `sbom/publications/<module>/<publication>/bom.xml`
- `sbom/publications/<module>/<publication>/bom.json.asc`
- `sbom/publications/<module>/<publication>/bom.xml.asc`

Examples:

- `supreme-common` Kotlin Multiplatform metadata: [JSON]({{ config.site_url }}/sbom/publications/supreme-common/kotlinMultiplatform/bom.json), [XML]({{ config.site_url }}/sbom/publications/supreme-common/kotlinMultiplatform/bom.xml)
- `supreme-common` JVM: [JSON]({{ config.site_url }}/sbom/publications/supreme-common/jvm/bom.json), [XML]({{ config.site_url }}/sbom/publications/supreme-common/jvm/bom.xml)
- `supreme-common` Android: [JSON]({{ config.site_url }}/sbom/publications/supreme-common/android/bom.json), [XML]({{ config.site_url }}/sbom/publications/supreme-common/android/bom.xml)
- `makoto` JVM: [JSON]({{ config.site_url }}/sbom/publications/makoto/mavenJava/bom.json), [XML]({{ config.site_url }}/sbom/publications/makoto/mavenJava/bom.xml)

Machine-readable index:

- [SBOM index JSON]({{ config.site_url }}/sbom/index.json)

The index is a lightweight discovery document for the documentation export. It lists each module/publication pair and
points to the corresponding JSON and XML SBOM files.

The per-module pages in the navigation are generated from that index and a shared Markdown template. Each generated
module page contains one row per published Maven publication, including artifact metadata and links to the corresponding
JSON/XML SBOM files, plus detached signature links when signature artifacts are present.

## Modules

- [Warden makoto](sbom/modules/makoto.md)
- [Warden roboto](sbom/modules/roboto.md)
- [Supreme Common](sbom/modules/supreme-common.md)
- [Supreme Client](sbom/modules/supreme-client.md)
- [Supreme Verifier](sbom/modules/supreme-verifier.md)
- [Config Hoplite](sbom/modules/config-hoplite.md)
- [Config Spring](sbom/modules/config-spring.md)

## Tooling

These SBOMs are standard CycloneDX documents and can be consumed directly by established tooling such as
Dependency-Track, OWASP Dependency-Check integrations that support CycloneDX, Syft/Grype workflows, and other
CycloneDX-compatible scanners and inventory systems.
