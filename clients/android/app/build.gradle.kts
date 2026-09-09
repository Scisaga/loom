import java.util.Base64 as JvmBase64

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

val platformPublicKeyFile = rootProject.file("../../deploy/keys/platform-signing.pub")
val platformPublicKeyB64 = sequenceOf(
    providers.gradleProperty("loomPlatformPublicKey").orNull,
    providers.environmentVariable("LOOM_PLATFORM_PUBLIC_KEY").orNull,
    platformPublicKeyFile.takeIf { it.isFile }?.readText(),
).filterNotNull().map(String::trim).firstOrNull(String::isNotEmpty).orEmpty()

if (platformPublicKeyB64.isNotEmpty()) {
    val decoded = runCatching { JvmBase64.getDecoder().decode(platformPublicKeyB64) }
        .getOrElse { throw GradleException("Loom platform public key is not canonical base64", it) }
    require(decoded.size == 32 && JvmBase64.getEncoder().encodeToString(decoded) == platformPublicKeyB64) {
        "Loom platform public key must be one canonical base64 Ed25519 public key"
    }
}

val requirePinnedTrustAnchor = tasks.register("requirePinnedTrustAnchor") {
    doLast {
        if (platformPublicKeyB64.isEmpty()) {
            throw GradleException(
                "Release builds require -PloomPlatformPublicKey, LOOM_PLATFORM_PUBLIC_KEY, " +
                    "or ../../deploy/keys/platform-signing.pub",
            )
        }
    }
}

val releaseSigningInputs = linkedMapOf(
    "LOOM_ANDROID_RELEASE_STORE_FILE" to providers.environmentVariable("LOOM_ANDROID_RELEASE_STORE_FILE").orNull,
    "LOOM_ANDROID_RELEASE_STORE_PASSWORD" to
        providers.environmentVariable("LOOM_ANDROID_RELEASE_STORE_PASSWORD").orNull,
    "LOOM_ANDROID_RELEASE_KEY_ALIAS" to providers.environmentVariable("LOOM_ANDROID_RELEASE_KEY_ALIAS").orNull,
    "LOOM_ANDROID_RELEASE_KEY_PASSWORD" to providers.environmentVariable("LOOM_ANDROID_RELEASE_KEY_PASSWORD").orNull,
).mapValues { (_, value) -> value.orEmpty() }
val releaseSigningConfigured = releaseSigningInputs.values.all(String::isNotEmpty)

val requireSigningInputs = tasks.register("requireSigningInputs") {
    doLast {
        val missing = releaseSigningInputs.filterValues(String::isEmpty).keys
        if (missing.isNotEmpty()) {
            throw GradleException("Release signing inputs are missing: ${missing.joinToString()}")
        }
        val store = file(releaseSigningInputs.getValue("LOOM_ANDROID_RELEASE_STORE_FILE"))
        if (!store.isFile) throw GradleException("Release signing store does not exist: $store")
    }
}

tasks.configureEach {
    if (name.contains("Release")) dependsOn(requirePinnedTrustAnchor, requireSigningInputs)
}

android {
    namespace = "io.github.scisaga.loom"
    compileSdk = 35
    buildToolsVersion = "35.0.1"

    defaultConfig {
        applicationId = "io.github.scisaga.loom"
        minSdk = 26
        targetSdk = 35
        versionCode = 5
        versionName = "0.4.0-rc1"

        buildConfigField("String", "LOOM_PLATFORM_PUBLIC_KEY_B64", "\"$platformPublicKeyB64\"")

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk { abiFilters += setOf("arm64-v8a", "x86_64") }
    }

    signingConfigs {
        create("release") {
            if (releaseSigningConfigured) {
                storeFile = file(releaseSigningInputs.getValue("LOOM_ANDROID_RELEASE_STORE_FILE"))
                storePassword = releaseSigningInputs.getValue("LOOM_ANDROID_RELEASE_STORE_PASSWORD")
                keyAlias = releaseSigningInputs.getValue("LOOM_ANDROID_RELEASE_KEY_ALIAS")
                keyPassword = releaseSigningInputs.getValue("LOOM_ANDROID_RELEASE_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            signingConfig = signingConfigs.getByName("release")
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    packaging {
        jniLibs.useLegacyPackaging = false
        resources.excludes += setOf("META-INF/LICENSE*", "META-INF/NOTICE*")
    }
}

dependencies {
    val cameraXVersion = "1.4.1"

    implementation(files("libs/loom-box.aar"))
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.activity:activity-compose:1.10.0")
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("androidx.camera:camera-camera2:$cameraXVersion")
    implementation("androidx.camera:camera-lifecycle:$cameraXVersion")
    implementation("androidx.camera:camera-view:$cameraXVersion")
    implementation("com.google.zxing:core:3.5.3")

    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation(platform("androidx.compose:compose-bom:2024.12.01"))
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test:rules:1.6.1")
    androidTestImplementation("androidx.test.uiautomator:uiautomator:2.3.0")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
}
