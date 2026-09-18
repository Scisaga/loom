plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

val sourceCommit = providers.gradleProperty("loomSourceCommit").orNull.orEmpty()
val aarSha256 = providers.gradleProperty("loomAarSha256").orNull.orEmpty()
val requireProvenance = tasks.register("requireProvenance") {
    doLast {
        require(sourceCommit.matches(Regex("[0-9a-f]{40}"))) { "Release requires canonical -PloomSourceCommit" }
        require(aarSha256.matches(Regex("[0-9a-f]{64}"))) { "Release requires canonical -PloomAarSha256" }
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
    if (name.contains("Release")) dependsOn(requireProvenance, requireSigningInputs)
}

android {
    namespace = "io.github.scisaga.loom"
    compileSdk = 35
    buildToolsVersion = "35.0.1"

    defaultConfig {
        applicationId = "io.github.scisaga.loom"
        minSdk = 26
        targetSdk = 35
        versionCode = 7
        versionName = "0.5.0"

        buildConfigField("String", "LOOM_SOURCE_COMMIT", "\"$sourceCommit\"")
        buildConfigField("String", "LOOM_AAR_SHA256", "\"$aarSha256\"")

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
