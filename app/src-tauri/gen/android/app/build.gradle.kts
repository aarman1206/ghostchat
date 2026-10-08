import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("rust")
}

val tauriProperties = Properties().apply {
    val propFile = file("tauri.properties")
    if (propFile.exists()) {
        propFile.inputStream().use { load(it) }
    }
}

val releaseSigningValues = listOf(
    "GHOSTCHAT_ANDROID_KEYSTORE" to System.getenv("GHOSTCHAT_ANDROID_KEYSTORE"),
    "GHOSTCHAT_ANDROID_STORE_PASSWORD" to System.getenv("GHOSTCHAT_ANDROID_STORE_PASSWORD"),
    "GHOSTCHAT_ANDROID_KEY_ALIAS" to System.getenv("GHOSTCHAT_ANDROID_KEY_ALIAS"),
    "GHOSTCHAT_ANDROID_KEY_PASSWORD" to System.getenv("GHOSTCHAT_ANDROID_KEY_PASSWORD"),
)
val releaseSigningConfigured = releaseSigningValues.any { !it.second.isNullOrBlank() }
if (releaseSigningConfigured && releaseSigningValues.any { it.second.isNullOrBlank() }) {
    throw GradleException(
        "Release signing requires GHOSTCHAT_ANDROID_KEYSTORE, " +
            "GHOSTCHAT_ANDROID_STORE_PASSWORD, GHOSTCHAT_ANDROID_KEY_ALIAS, and " +
            "GHOSTCHAT_ANDROID_KEY_PASSWORD."
    )
}

android {
    compileSdk = 36
    namespace = "org.lord.ghostchat"
    // This Gradle native build compiles GhostChat's JNI bridge with r29.
    // The separately source-built Tor payload uses Guardian's pinned NDK r30
    // recipe and is packaged from src/main/jniLibs.
    ndkVersion = "29.0.13846066"
    defaultConfig {
        manifestPlaceholders["usesCleartextTraffic"] = "false"
        applicationId = "org.lord.ghostchat"
        minSdk = 24
        targetSdk = 36
        versionCode = tauriProperties.getProperty("tauri.android.versionCode", "1").toInt()
        versionName = tauriProperties.getProperty("tauri.android.versionName", "1.0")
    }
    signingConfigs {
        if (releaseSigningConfigured) {
            create("providedRelease") {
                storeFile = file(System.getenv("GHOSTCHAT_ANDROID_KEYSTORE")!!)
                storePassword = System.getenv("GHOSTCHAT_ANDROID_STORE_PASSWORD")!!
                keyAlias = System.getenv("GHOSTCHAT_ANDROID_KEY_ALIAS")!!
                keyPassword = System.getenv("GHOSTCHAT_ANDROID_KEY_PASSWORD")!!
            }
        }
    }
    buildTypes {
        getByName("debug") {
            manifestPlaceholders["usesCleartextTraffic"] = "true"
            isDebuggable = true
            isJniDebuggable = true
            isMinifyEnabled = false
            packaging {                jniLibs.keepDebugSymbols.add("*/arm64-v8a/*.so")
                jniLibs.keepDebugSymbols.add("*/armeabi-v7a/*.so")
                jniLibs.keepDebugSymbols.add("*/x86/*.so")
                jniLibs.keepDebugSymbols.add("*/x86_64/*.so")
            }
        }
        getByName("release") {
            isMinifyEnabled = true
            if (releaseSigningConfigured) {
                signingConfig = signingConfigs.getByName("providedRelease")
            }
            proguardFiles(
                *fileTree(".") { include("**/*.pro") }
                    .plus(getDefaultProguardFile("proguard-android-optimize.txt"))
                    .toList().toTypedArray()
            )
        }
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
    buildFeatures {
        buildConfig = true
    }
    externalNativeBuild {
        ndkBuild {
            path = file("src/main/jni/Android.mk")
        }
    }
}

rust {
    rootDirRel = "../../../"
}

dependencies {
    implementation("androidx.webkit:webkit:1.14.0")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.activity:activity-ktx:1.10.1")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.lifecycle:lifecycle-process:2.10.0")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.4")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.0")
}

apply(from = "tauri.build.gradle.kts")
