import java.io.StringReader
import java.util.Properties

plugins {
    id("com.android.library") version "8.13.2"
    id("org.jetbrains.kotlin.android") version "2.2.21"
    `maven-publish`
}

val nodeVersion = providers.gradleProperty("gnunetNodeVersion")
val nodeArchives = providers.gradleProperty("gnunetNodeArchives")
    .orElse(layout.projectDirectory.dir("../../target/android-node-archives").asFile.absolutePath)
val profileText = providers.fileContents(layout.projectDirectory.file("sdk-profile.properties")).asText
val sdkProfile = Properties().apply { load(StringReader(profileText.get())) }
fun profileValue(key: String) = requireNotNull(sdkProfile.getProperty(key)) {
    "Missing Android SDK profile property: $key"
}
val supportedAbis = sdkProfile.stringPropertyNames()
    .filter { it.startsWith("target.") }.map { it.removePrefix("target.") }.toSet()
val nodeAbis = providers.gradleProperty("gnunetNodeAbis")
    .map { it.split(',').map(String::trim).toSet() }
    .getOrElse(supportedAbis)
require(nodeAbis.isNotEmpty() && supportedAbis.containsAll(nodeAbis)) {
    "gnunetNodeAbis must be a comma-separated list of Android ABIs: $supportedAbis"
}

android {
    namespace = "org.gnunet.sdk"
    compileSdk = profileValue("compileSdk").toInt()
    buildToolsVersion = profileValue("buildTools")
    ndkVersion = profileValue("ndk")

    defaultConfig {
        minSdk = profileValue("minSdk").toInt()
        consumerProguardFiles("consumer-rules.pro")
        ndk { abiFilters.addAll(nodeAbis) }
        externalNativeBuild {
            cmake { arguments += "-DGNUNET_NODE_ARCHIVES=${file(nodeArchives.get()).absolutePath}" }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = profileValue("cmake")
        }
    }

    publishing {
        singleVariant("release")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) }
}

if (nodeVersion.isPresent) {
    publishing {
        publications {
            register<MavenPublication>("release") {
                groupId = "io.github.noctiro"
                artifactId = "gnunet-node-android"
                version = nodeVersion.get()
                pom {
                    name.set("GNUnet Node Android SDK")
                    licenses {
                        license {
                            name.set("Mozilla Public License 2.0")
                            url.set("https://www.mozilla.org/en-US/MPL/2.0/")
                        }
                    }
                }
                afterEvaluate { from(components["release"]) }
            }
        }
        repositories {
            maven {
                name = "Sdk"
                url = uri(layout.buildDirectory.dir("sdk-repository"))
            }
        }
    }
}
