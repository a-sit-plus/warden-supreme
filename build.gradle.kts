import groovy.json.JsonSlurper
import org.gradle.api.publish.maven.tasks.PublishToMavenLocal
import org.gradle.api.publish.maven.tasks.PublishToMavenRepository
import org.gradle.api.tasks.bundling.Jar

plugins {
    val kotlinVer = System.getenv("KOTLIN_VERSION_ENV")?.ifBlank { null } ?: libs.versions.kotlin.get()
    val testballoonVer =
        System.getenv("TESTBALLOON_VERSION_OVERRIDE")?.ifBlank { null } ?: libs.versions.testballoon.get()

    id("de.infix.testBalloon") version testballoonVer apply false
    kotlin("jvm") version kotlinVer apply false
    kotlin("plugin.serialization") version kotlinVer apply false
    id("maven-publish")
    alias(libs.plugins.asp)
    alias(libs.plugins.agp) apply (false)
    alias(libs.plugins.sbombastic)
    alias(libs.plugins.pitest) apply false
    alias(libs.plugins.composeMultiplatform) apply false
    alias(libs.plugins.composeCompiler) apply false
    alias(libs.plugins.ktor) apply false
    alias(libs.plugins.androidApplication) apply false
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

    val githubActor = findProperty("gpr.user") as String? ?: System.getenv("GITHUB_ACTOR")
    val githubToken = findProperty("gpr.key") as String? ?: System.getenv("GITHUB_TOKEN")
    val githubRepository =
        findProperty("gpr.repo") as String? ?: System.getenv("GITHUB_REPOSITORY") ?: "a-sit-plus/warden-supreme"
    afterEvaluate {
        if (githubToken != null && githubActor != null) {
            publishing.repositories.maven {
                name = "GitHubPackages"
                url = uri("https://maven.pkg.github.com/$githubRepository")
                credentials {
                    username = githubActor
                    password = githubToken
                }
            }
        }
    }
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
    project(":generator"),
)

listOf(project(":collector-app"), project(":collector-backend"), project(":collector-shared")).forEach {
    it.tasks.withType<PublishToMavenLocal>().configureEach { enabled = false }
    it.tasks.withType<PublishToMavenRepository>().configureEach { enabled = false }
}

publishedProjects.forEach { moduleProject ->
    moduleProject.tasks.register<Jar>("javadocRedirectJar") {
        archiveClassifier.set("javadoc")
        from(rootProject.layout.projectDirectory.dir("docs/javadoc"))
    }
}

val releasePublicationsByProject = linkedMapOf(
    ":makoto" to listOf("mavenJava"),
    ":roboto" to listOf("mavenJava"),
    ":config-hoplite" to listOf("mavenJava"),
    ":config-spring" to listOf("mavenJava"),
    ":supreme-common" to listOf("android", "iosArm64", "iosSimulatorArm64", "jvm", "kotlinMultiplatform"),
    ":supreme-client" to listOf("android", "iosArm64", "iosSimulatorArm64", "kotlinMultiplatform"),
    ":supreme-verifier" to listOf("jvm", "kotlinMultiplatform"),
    ":generator" to listOf("mavenJava"),
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

val syncSbomDocs by tasks.register("syncSbomDocs") {
    group = "documentation"
    description = "Exports CycloneDX SBOMs for all published Maven publications into the docs tree."

    val sbomDocsDir = rootProject.layout.projectDirectory.dir("docs/docs/sbom")
    val sbomIndexFile = rootProject.layout.projectDirectory.file("docs/docs/sbom/index.json")
    val sbomTemplateFile = rootProject.layout.projectDirectory.file("docs/templates/sbom-module.template.md")
    val sbomRendererFile = rootProject.layout.projectDirectory.file("docs/tools/render_sbom_pages.py")
    val sortedProjects = publishedProjects.sortedBy { it.name }

    // Depend on the *Normalized* task, not the base one: `cyclonedx<Pub>PublicationBom` only emits `bom.raw.{json,xml}`;
    // the normalized `bom.json` we parse below (the one carrying the `…?…&type=` purl) is produced by
    // `…PublicationBomNormalized`. Depending on the base task left `bom.json` absent on clean CI checkouts, so `entries`
    // came out empty and no module pages were rendered — which then failed the strict mkdocs build.
    val bomJsonFiles = releasePublicationsByProject.flatMap { (projectPath, publicationNames) ->
        publicationNames.map { publicationName ->
            project(projectPath).layout.buildDirectory.file("reports/cyclonedx-publications/$publicationName/bom.json")
        }
    }
    dependsOn(releasePublicationsByProject.flatMap { (projectPath, publicationNames) ->
        publicationNames.map { publicationName ->
            "$projectPath:cyclonedx${publicationName.replaceFirstChar { it.uppercase() }}PublicationBomNormalized"
        }
    })
    inputs.files(bomJsonFiles)
    inputs.file(sbomTemplateFile)
    inputs.file(sbomRendererFile)
    outputs.file(sbomIndexFile)
    outputs.dir(sbomDocsDir.dir("modules"))

    doLast {
        val jsonSlurper = JsonSlurper()
        val sbomPublicationsDir = sbomDocsDir.dir("publications").asFile
        val mavenCentralBaseUrl = "https://repo1.maven.org/maven2"
        val entries = sortedProjects.flatMap { moduleProject ->
            val publicationRoot = moduleProject.layout.buildDirectory.dir("reports/cyclonedx-publications").get().asFile
            releasePublicationsByProject[moduleProject.path].orEmpty().mapNotNull { publicationName ->
                val publicationDir = publicationRoot.resolve(publicationName)
                val bomJsonFile = publicationDir.resolve("bom.json")
                check(bomJsonFile.isFile) {
                    "Expected normalized CycloneDX SBOM at $bomJsonFile for ${moduleProject.path} publication " +
                        "'$publicationName', but it is missing. Ensure " +
                        "cyclonedx${publicationName.replaceFirstChar { it.uppercase() }}PublicationBomNormalized ran."
                }

                @Suppress("UNCHECKED_CAST")
                val bom = jsonSlurper.parse(bomJsonFile) as Map<String, Any?>

                @Suppress("UNCHECKED_CAST")
                val metadata = bom["metadata"] as? Map<String, Any?> ?: emptyMap()

                @Suppress("UNCHECKED_CAST")
                val component = metadata["component"] as? Map<String, Any?> ?: emptyMap()
                val groupId = component["group"]?.toString().orEmpty()
                val artifactId = component["name"]?.toString().orEmpty()
                val version = component["version"]?.toString().orEmpty()
                // Extrapolate the packaging from the CycloneDX purl (`…?…&type=jar|aar|klib`) rather than scanning the
                // locally published `repo/` tree. We only ever *link* to the SBOMs published on Maven Central, so full
                // docs can be generated without publishing (and therefore without signing) any artefacts locally.
                val purl = component["purl"]?.toString().orEmpty()
                val packaging = Regex("[?&]type=([^&]+)").find(purl)?.groupValues?.get(1).orEmpty()

                val mavenCentralArtifactBase = buildString {
                    append(mavenCentralBaseUrl)
                    append("/")
                    append(groupId.replace('.', '/'))
                    append("/")
                    append(artifactId)
                    append("/")
                    append(version)
                    append("/")
                    append(artifactId)
                    append("-")
                    append(version)
                    append("-cyclonedx")
                }
                val jsonUrl = "$mavenCentralArtifactBase.json"
                val xmlUrl = "$mavenCentralArtifactBase.xml"

                linkedMapOf(
                    "module" to moduleProject.name,
                    "publication" to publicationName,
                    "kind" to if (publicationName == "kotlinMultiplatform") "metadata" else "target",
                    "groupId" to groupId,
                    "artifactId" to artifactId,
                    "version" to version,
                    "packaging" to packaging,
                    "json" to jsonUrl,
                    "xml" to xmlUrl,
                    "jsonSig" to "$jsonUrl.asc",
                    "xmlSig" to "$xmlUrl.asc",
                    "mavenCentralClassifier" to "cyclonedx",
                )
            }
        }
        check(entries.isNotEmpty()) {
            "No CycloneDX SBOMs were found for any published publication. The generated docs would reference module " +
                "pages that are never created, failing the strict mkdocs build. Check that the cyclonedx…" +
                "PublicationBomNormalized tasks produced reports/cyclonedx-publications/<publication>/bom.json."
        }
        val sbomModulesDir = sbomDocsDir.dir("modules").asFile
        sbomPublicationsDir.deleteRecursively()
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

/** The shaded CLI, shipped with the documentation so it can be downloaded from the Testing page. */
val copyGeneratorCli = tasks.register<Copy>("copyGeneratorCli") {
    from(project(":generator").tasks.named("shadowJar")) { rename { "attestation-generator.jar" } }
    into(rootDir.resolve("docs/docs/downloads"))
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
    dependsOn(project(":generator").tasks.named<Test>("test") {
        setTestNameIncludePatterns(listOf("examples.*"))
    }) //to generate the attestation generator's example configurations
    dependsOn(copyGeneratorCli)
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
