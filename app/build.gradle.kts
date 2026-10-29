plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

/*
 * GeDefense TV is deliberately built without AndroidX or any other third-party runtime
 * dependency. The TV UI, D-pad focus handling, collectors and evidence chain are implemented
 * against the Android platform APIs plus the vendored, dependency-free GeDefense core.
 */

val releaseStoreFile = System.getenv("GEDEFENSE_RELEASE_STORE_FILE")
val releaseStorePassword = System.getenv("GEDEFENSE_RELEASE_STORE_PASSWORD")
val releaseKeyAlias = System.getenv("GEDEFENSE_RELEASE_KEY_ALIAS")
val releaseKeyPassword = System.getenv("GEDEFENSE_RELEASE_KEY_PASSWORD")

android {
    namespace = "de.visiongaia.gedefense.tv"
    compileSdk = 36
    buildToolsVersion = "36.0.0"

    defaultConfig {
        applicationId = "de.visiongaia.gedefense.tv"
        minSdk = 26
        targetSdk = 36
        versionCode = 3
        versionName = "0.2.0-alpha2"
        // SECV2-13: pin the audited GaiaNet helper per ABI; NativeGaiaNet verifies before exec.
        buildConfigField("String", "GAIANET_SHA_ARM64", "\"d34fda6f06ed7809c386af243b55e55cadd20794f1413b94ada3a729b26fd15e\"")
        buildConfigField("String", "GAIANET_SHA_X86_64", "\"9f393ce49032a84f75717174b09748c08e86ff831886a38f68d0ac12975394f3\"")
        ndk {
            // The loopback VPN data plane is the vendored, audited GaiaNet helper (same binary as
            // GeDefense Mobile): 64-bit ARM for real TVs, x86_64 for the TV emulator.
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    signingConfigs {
        if (releaseStoreFile != null && releaseStorePassword != null && releaseKeyAlias != null && releaseKeyPassword != null) {
            create("release") {
                storeFile = file(releaseStoreFile)
                storePassword = releaseStorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
            }
        }
    }

    buildTypes {
        release {
            isDebuggable = false
            isMinifyEnabled = true
            isShrinkResources = true
            // SECV2-01: never fall back to the well-known Android debug key for a release artefact.
            // A missing signing configuration fails the build instead of silently producing an
            // un-upgradable, publicly reproducible debug-signed APK.
            // SECV2-01: debug builds need no signing env; release build validation is below.
            signingConfig = signingConfigs.findByName("release")
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
        freeCompilerArgs += listOf("-Xjsr305=strict")
    }

    buildFeatures {
        buildConfig = true
    }

    lint {
        warningsAsErrors = false
        abortOnError = true
        checkReleaseBuilds = true
    }

    packaging {
        resources.excludes += setOf("META-INF/*.kotlin_module")
        // The GaiaNet helper must be a real executable file in nativeLibraryDir to be launched as a
        // child process; legacy (extracted) packaging is mandatory for the native data plane.
        jniLibs.useLegacyPackaging = true
        jniLibs.keepDebugSymbols += setOf("**/*.so")
    }
}

afterEvaluate {
    tasks.matching { it.name == "assembleRelease" || it.name == "bundleRelease" }.configureEach {
        doFirst {
            if (android.signingConfigs.findByName("release") == null) {
                throw org.gradle.api.GradleException(
                    "Release signing requires GEDEFENSE_RELEASE_STORE_FILE / _PASSWORD / _KEY_ALIAS / _KEY_PASSWORD. " +
                        "Use _keys/signing-env.ps1 to configure an alpha/production keystore."
                )
            }
        }
    }
}

dependencies {
    implementation(project(":core"))
    implementation(project(":tv-core"))
}
