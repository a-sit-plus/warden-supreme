import org.gradle.api.publish.PublishingExtension
import org.gradle.api.publish.maven.MavenPublication

plugins {
    val kotlinVer = System.getenv("KOTLIN_VERSION_ENV")?.ifBlank { null } ?: libs.versions.kotlin.get()
    val testballoonVer =
        System.getenv("TESTBALLOON_VERSION_OVERRIDE")?.ifBlank { null } ?: libs.versions.testballoon.get()

    id("de.infix.testBalloon") version testballoonVer apply false
    kotlin("jvm") version kotlinVer apply false
    kotlin("plugin.serialization") version kotlinVer apply false
    alias(libs.plugins.asp)
    alias(libs.plugins.agp) apply (false)
    alias(libs.plugins.sbombastic)
}

val artifactVersion: String by extra
val groupId: String by extra
group = groupId
version = artifactVersion


val dokkaDir = rootProject.layout.buildDirectory.dir("dokka")
dokka {
    dokkaPublications.html {
        outputDirectory.set(dokkaDir)
    }
}

subprojects {
    rootProject.dependencies.add("dokka", this)
}

allprojects {
    apply(plugin = "org.jetbrains.dokka")
    group = rootProject.group
}

tasks.register<Copy>("copyChangelog") {
    into(rootDir.resolve("docs/docs"))
    from("CHANGELOG.md")
}

val publishedProjects = listOf(
    project(":makoto"),
    project(":roboto"),
    project(":supreme-common"),
    project(":supreme-client"),
    project(":supreme-verifier"),
    project(":config-hoplite"),
    project(":config-spring"),
)

val syncSbomDocs by tasks.register<Sync>("syncSbomDocs") {
    group = "documentation"
    description = "Exports CycloneDX SBOMs for all published Maven publications into the docs tree."

    val sbomDocsDir = rootProject.layout.projectDirectory.dir("docs/docs/sbom")
    val sbomIndexFile = rootProject.layout.projectDirectory.file("docs/docs/sbom/index.json")
    val sbomTemplateFile = rootProject.layout.projectDirectory.file("docs/templates/sbom-module.template.md")
    val sbomRendererFile = rootProject.layout.projectDirectory.file("docs/tools/render_sbom_pages.py")
    val sortedProjects = publishedProjects.sortedBy { it.name }

    dependsOn(sortedProjects.map { project ->
        project.tasks.matching { task -> task.name == "cyclonedxPublishedBom" }
    })
    inputs.file(sbomTemplateFile)
    inputs.file(sbomRendererFile)

    into(sbomDocsDir)
    sortedProjects.forEach { moduleProject ->
        from(moduleProject.layout.buildDirectory.dir("reports/cyclonedx-publications")) {
            include("*/bom.json", "*/bom.xml", "*/bom.json.asc", "*/bom.xml.asc")
            into("publications/${moduleProject.name}")
        }
    }

    doLast {
        val entries = sortedProjects.flatMap { moduleProject ->
            val publicationRoot = moduleProject.layout.buildDirectory.dir("reports/cyclonedx-publications").get().asFile
            val publishing = moduleProject.extensions.findByType(PublishingExtension::class.java)
            val publications = publishing
                ?.publications
                ?.withType(MavenPublication::class.java)
                ?.associateBy { it.name }
                .orEmpty()

            publicationRoot
                .listFiles { file -> file.isDirectory }
                .orEmpty()
                .sortedBy { it.name }
                .map { publicationDir ->
                    val publication = publications[publicationDir.name]
                    val primaryArtifact = publication
                        ?.artifacts
                        ?.firstOrNull { artifact ->
                            artifact.classifier.isNullOrBlank() && artifact.extension !in setOf("module", "pom")
                        }
                    val jsonSig = publicationDir.resolve("bom.json.asc").takeIf { it.isFile }?.let {
                        "publications/${moduleProject.name}/${publicationDir.name}/bom.json.asc"
                    }
                    val xmlSig = publicationDir.resolve("bom.xml.asc").takeIf { it.isFile }?.let {
                        "publications/${moduleProject.name}/${publicationDir.name}/bom.xml.asc"
                    }

                    linkedMapOf(
                        "module" to moduleProject.name,
                        "publication" to publicationDir.name,
                        "kind" to if (publicationDir.name == "kotlinMultiplatform") "metadata" else "target",
                        "groupId" to (publication?.groupId ?: rootProject.group.toString()),
                        "artifactId" to (publication?.artifactId ?: moduleProject.name),
                        "version" to (publication?.version ?: rootProject.version.toString()),
                        "packaging" to (primaryArtifact?.extension ?: ""),
                        "json" to "publications/${moduleProject.name}/${publicationDir.name}/bom.json",
                        "xml" to "publications/${moduleProject.name}/${publicationDir.name}/bom.xml",
                        "jsonSig" to (jsonSig ?: ""),
                        "xmlSig" to (xmlSig ?: ""),
                        "mavenCentralClassifier" to "cyclonedx",
                    )
                }
        }
        val sbomModulesDir = sbomDocsDir.dir("modules").asFile
        sbomModulesDir.mkdirs()

        val json = buildString {
            appendLine("{")
            appendLine("  \"format\": \"CycloneDX\",")
            appendLine("  \"version\": 1,")
            appendLine("  \"entries\": [")
            entries.forEachIndexed { index, entry ->
                val comma = if (index == entries.lastIndex) "" else ","
                appendLine("    {")
                entry.entries.forEachIndexed { fieldIndex, field ->
                    val escapedValue = field.value
                        .replace("\\", "\\\\")
                        .replace("\"", "\\\"")
                    val fieldComma = if (fieldIndex == entry.size - 1) "" else ","
                    appendLine("      \"${field.key}\": \"$escapedValue\"$fieldComma")
                }
                appendLine("    }$comma")
            }
            appendLine("  ]")
            appendLine("}")
        }

        sbomIndexFile.asFile.parentFile.mkdirs()
        sbomIndexFile.asFile.writeText(json)
        val process = ProcessBuilder(
            "python3",
            sbomRendererFile.asFile.absolutePath,
            "--index",
            sbomIndexFile.asFile.absolutePath,
            "--template",
            sbomTemplateFile.asFile.absolutePath,
            "--output-dir",
            sbomModulesDir.absolutePath,
        )
            .directory(rootDir)
            .inheritIO()
            .start()
        val exitCode = process.waitFor()
        check(exitCode == 0) {
            "SBOM module page rendering failed with exit code $exitCode"
        }
    }
}

tasks.register<Copy>("mkDocsPrepare") {
    dependsOn("dokkaGenerate")
    dependsOn("copyChangelog")
    dependsOn(syncSbomDocs)
    dependsOn(project(":supreme-common").tasks.named<Test>("jvmTest") {
        setTestNameIncludePatterns(listOf("examples.*"))
    }) //to generate JSON schema
    dependsOn(project(":supreme-verifier").tasks.named<Test>("jvmTest") {
        setTestNameIncludePatterns(listOf("examples.*"))
    }) //to generate config files
    into(rootDir.resolve("docs/docs/dokka"))
    from(dokkaDir)
}

tasks.register<Exec>("mkDocsBuild") {
    dependsOn(tasks.named("mkDocsPrepare"))
    workingDir("${rootDir}/docs")
    commandLine("mkdocs", "build", "--clean", "--strict")
}

tasks.register<Copy>("mkDocsSite") {
    dependsOn("mkDocsBuild")
    into(rootDir.resolve("docs/site/assets/images/social"))
    from(rootDir.resolve("docs/docs/assets/images/social"))
}
