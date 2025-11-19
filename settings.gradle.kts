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
project(":supreme-verifier").projectDir = file("supreme/verifier")
include("supreme-common")
project(":supreme-common").projectDir = file("supreme/common")
include("supreme-client")
project(":supreme-client").projectDir = file("supreme/client")
include("supreme-swiftclient")
project(":supreme-swiftclient").projectDir = file("supreme/client-swift")