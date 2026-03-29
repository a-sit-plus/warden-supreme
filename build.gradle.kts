import groovy.json.JsonSlurper
import org.gradle.plugins.signing.Sign

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
    alias(libs.plugins.pitest) apply false
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

val releasePublicationsByProject = linkedMapOf(
    ":makoto" to listOf("mavenJava"),
    ":roboto" to listOf("mavenJava"),
    ":config-hoplite" to listOf("mavenJava"),
    ":config-spring" to listOf("mavenJava"),
    ":supreme-common" to listOf("android", "iosArm64", "iosSimulatorArm64", "iosX64", "jvm", "kotlinMultiplatform"),
    ":supreme-client" to listOf("android", "iosArm64", "iosSimulatorArm64", "iosX64", "kotlinMultiplatform"),
    ":supreme-verifier" to listOf("jvm", "kotlinMultiplatform"),
)

tasks.register("publishReleaseModulesToSonatype") {
    group = "publishing"
    description = "Publishes only the release modules declared in publishedProjects to Sonatype."
    dependsOn(releasePublicationsByProject.flatMap { (projectPath, publicationNames) ->
        publicationNames.map { publicationName ->
            "$projectPath:publish${publicationName.replaceFirstChar { it.uppercase() }}PublicationToSonatypeRepository"
        }
    })
}

tasks.register("publishReleaseModulesToLocalRepository") {
    group = "publishing"
    description = "Publishes only the release modules declared in publishedProjects to the project-local repo."
    dependsOn(releasePublicationsByProject.flatMap { (projectPath, publicationNames) ->
        publicationNames.map { publicationName ->
            "$projectPath:publish${publicationName.replaceFirstChar { it.uppercase() }}PublicationToLocalRepository"
        }
    })
}

tasks.register("loaderMutationTest") {
    group = "verification"
    description = "Runs mutation testing for the dedicated config loader adapter modules."
    dependsOn(
        ":config-hoplite:pitest",
        ":config-spring:pitest",
    )
}

val signLocalRepoArtefacts = System.getenv("SIGN_LOCAL_REPO_ARTEFACTS")?.ifBlank { "false" } == "true"

val syncSbomDocs by tasks.register<Sync>("syncSbomDocs") {
    group = "documentation"
    description = "Exports CycloneDX SBOMs for all published Maven publications into the docs tree."

    val sbomDocsDir = rootProject.layout.projectDirectory.dir("docs/docs/sbom")
    val sbomIndexFile = rootProject.layout.projectDirectory.file("docs/docs/sbom/index.json")
    val sbomTemplateFile = rootProject.layout.projectDirectory.file("docs/templates/sbom-module.template.md")
    val sbomRendererFile = rootProject.layout.projectDirectory.file("docs/tools/render_sbom_pages.py")
    val sortedProjects = publishedProjects.sortedBy { it.name }

    dependsOn(releasePublicationsByProject.flatMap { (projectPath, publicationNames) ->
        publicationNames.map { publicationName ->
            "$projectPath:cyclonedx${publicationName.replaceFirstChar { it.uppercase() }}PublicationBom"
        }
    })
    if (signLocalRepoArtefacts) {
        dependsOn(sortedProjects.map { project ->
            project.tasks.withType(Sign::class.java)
        })
    }
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
        val jsonSlurper = JsonSlurper()
        val repoRoot = rootProject.layout.projectDirectory.dir("repo").asFile
        val entries = sortedProjects.flatMap { moduleProject ->
            val publicationRoot = moduleProject.layout.buildDirectory.dir("reports/cyclonedx-publications").get().asFile
            releasePublicationsByProject[moduleProject.path].orEmpty().mapNotNull { publicationName ->
                val publicationDir = publicationRoot.resolve(publicationName)
                val bomJsonFile = publicationDir.resolve("bom.json")
                if (!bomJsonFile.isFile) return@mapNotNull null

                @Suppress("UNCHECKED_CAST")
                val bom = jsonSlurper.parse(bomJsonFile) as Map<String, Any?>
                @Suppress("UNCHECKED_CAST")
                val metadata = bom["metadata"] as? Map<String, Any?> ?: emptyMap()
                @Suppress("UNCHECKED_CAST")
                val component = metadata["component"] as? Map<String, Any?> ?: emptyMap()
                val groupId = component["group"]?.toString().orEmpty()
                val artifactId = component["name"]?.toString().orEmpty()
                val version = component["version"]?.toString().orEmpty()
                val artifactDir = repoRoot.resolve(groupId.replace('.', '/')).resolve(artifactId).resolve(version)
                val packaging = artifactDir
                    .listFiles()
                    .orEmpty()
                    .mapNotNull { artifactFile ->
                        artifactFile.name
                            .removePrefix("$artifactId-$version.")
                            .takeIf {
                                artifactFile.isFile &&
                                    artifactFile.name.startsWith("$artifactId-$version.") &&
                                    it !in setOf(
                                        "pom",
                                        "module",
                                        "json",
                                        "xml",
                                        "jar.asc",
                                        "aar.asc",
                                        "klib.asc",
                                        "module.asc",
                                        "pom.asc",
                                        "json.asc",
                                        "xml.asc",
                                        "javadoc.jar",
                                        "sources.jar",
                                        "kotlin-tooling-metadata.json",
                                        "metadata.jar",
                                    ) &&
                                    !artifactFile.name.endsWith(".md5") &&
                                    !artifactFile.name.endsWith(".sha1") &&
                                    !artifactFile.name.endsWith(".sha256") &&
                                    !artifactFile.name.endsWith(".sha512")
                            }
                    }
                    .firstOrNull()
                    ?: ""

                val jsonSig = publicationDir.resolve("bom.json.asc").takeIf { it.isFile }?.let {
                    "publications/${moduleProject.name}/${publicationName}/bom.json.asc"
                }
                val xmlSig = publicationDir.resolve("bom.xml.asc").takeIf { it.isFile }?.let {
                    "publications/${moduleProject.name}/${publicationName}/bom.xml.asc"
                }

                linkedMapOf(
                    "module" to moduleProject.name,
                    "publication" to publicationName,
                    "kind" to if (publicationName == "kotlinMultiplatform") "metadata" else "target",
                    "groupId" to groupId,
                    "artifactId" to artifactId,
                    "version" to version,
                    "packaging" to packaging,
                    "json" to "publications/${moduleProject.name}/${publicationName}/bom.json",
                    "xml" to "publications/${moduleProject.name}/${publicationName}/bom.xml",
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
