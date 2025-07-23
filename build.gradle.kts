import org.jetbrains.dokka.gradle.DokkaMultiModuleTask

plugins {
    id("at.asitplus.gradle.conventions") version "2.1.20+20250409"
    id("com.android.library") version "8.6.1" apply (false)
}

group = "at.asitplus.wardensupreme"


//access dokka plugin from conventions plugin's classpath in root project → no need to specify version
apply(plugin = "org.jetbrains.dokka")
tasks.getByName("dokkaHtmlMultiModule") {
    (this as DokkaMultiModuleTask)
    outputDirectory.set(File("$buildDir/dokka"))
    includes.from("README.md")
    moduleName.set("WARDEN Supreme")
}


allprojects {
    repositories {
        mavenLocal()
    }
}