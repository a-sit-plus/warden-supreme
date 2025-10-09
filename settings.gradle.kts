rootProject.name = "Warden-Supreme"
pluginManagement {
    repositories {
        maven {
            url = uri("https://raw.githubusercontent.com/a-sit-plus/gradle-conventions-plugin/mvn/repo")
            name = "aspConventions"
        }
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

include("makoto")
include("makoto-diag")
include("roboto")
include("roboto-diag")
project(":makoto").projectDir = file("serverside/makoto")
project(":roboto").projectDir = file("serverside/roboto")
project(":roboto-diag").projectDir = file("utils/roboto-diag")
project(":makoto-diag").projectDir = file("utils/makoto-diag")



include("supreme-verifier")
include("supreme-common")
include("supreme-client")
project(":supreme-verifier").projectDir = file("supreme/verifier")
project(":supreme-common").projectDir = file("supreme/common")
project(":supreme-client").projectDir = file("supreme/client")

if (System.getProperty("publishing.excludeIncludedBuilds") != "true") {
    includeBuild("dependencies/signum")
} else logger.lifecycle("Excluding Signum from this build")
