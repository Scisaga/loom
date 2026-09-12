import java.util.Base64 as JvmBase64
import groovy.json.JsonOutput
import java.security.MessageDigest
import java.time.Instant

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
        versionCode = 6
        versionName = "0.4.0-rc2"

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
    dependenciesInfo {
        // #14：AGP 每次以新随机量加密这份重复的 SDK 索引；已审计的确定性 SPDX 才是依赖 SSOT。
        includeInApk = false
        includeInBundle = false
    }
    sourceSets.getByName("main").assets.srcDir(rootProject.file("third_party"))
    sourceSets.getByName("androidTest").assets.srcDir(rootProject.file("../../testdata"))
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

tasks.register("generateAndroidSbom") {
    val runtime = configurations.named("releaseRuntimeClasspath")
    val nativeAar = layout.projectDirectory.file("libs/loom-box.aar")
    val output = layout.buildDirectory.file("reports/sbom/loom-android-release.spdx.json")
    inputs.files(runtime)
    inputs.file(nativeAar)
    inputs.property("sourceDateEpoch", providers.environmentVariable("SOURCE_DATE_EPOCH").orElse("0"))
    outputs.file(output)

    doLast {
        fun sha256(file: File): String {
            val digest = MessageDigest.getInstance("SHA-256")
            file.inputStream().buffered().use { input ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    digest.update(buffer, 0, count)
                }
            }
            return digest.digest().joinToString("") { "%02x".format(it) }
        }

        val artifacts = runtime.get().resolvedConfiguration.resolvedArtifacts
            .sortedBy {
                val id = it.moduleVersion.id
                "${id.group}:${id.name}:${id.version}:${it.name}:${it.classifier.orEmpty()}:${it.extension}"
            }
        val dependencyRecords = artifacts.mapIndexed { index, artifact ->
            val id = artifact.moduleVersion.id
            val packageName = "${id.group}:${id.name}"
            val spdxID = "SPDXRef-Maven-${index + 1}"
            val digest = sha256(artifact.file)
            val sbomPackage = linkedMapOf<String, Any>(
                "name" to packageName,
                "SPDXID" to spdxID,
                "versionInfo" to id.version,
                "downloadLocation" to "NOASSERTION",
                "filesAnalyzed" to false,
                "checksums" to listOf(
                    mapOf("algorithm" to "SHA256", "checksumValue" to digest),
                ),
                "licenseConcluded" to "NOASSERTION",
                "licenseDeclared" to "NOASSERTION",
                "copyrightText" to "NOASSERTION",
                "externalRefs" to listOf(
                    mapOf(
                        "referenceCategory" to "PACKAGE-MANAGER",
                        "referenceType" to "purl",
                        "referenceLocator" to "pkg:maven/${id.group}/${id.name}@${id.version}",
                    ),
                ),
            )
            Triple(sbomPackage, "$packageName\u0000${id.version}\u0000$digest", spdxID)
        }
        val nativeDigest = sha256(nativeAar.asFile)
        val nativePackage = linkedMapOf<String, Any>(
            "name" to "sing-box-libbox",
            "SPDXID" to "SPDXRef-Native-Libbox",
            "versionInfo" to "1.11.4",
            "downloadLocation" to "NOASSERTION",
            "filesAnalyzed" to false,
            "checksums" to listOf(
                mapOf("algorithm" to "SHA256", "checksumValue" to nativeDigest),
            ),
            "licenseConcluded" to "GPL-3.0-or-later",
            "licenseDeclared" to "GPL-3.0-or-later",
            "copyrightText" to "NOASSERTION",
            "externalRefs" to listOf(
                mapOf(
                    "referenceCategory" to "OTHER",
                    "referenceType" to "vcs",
                    "referenceLocator" to
                        "git+https://github.com/SagerNet/sing-box@eb07c7a79eeca943370eafea601e87da76c0e57e",
                ),
            ),
        )
        val inventory = (dependencyRecords.map { it.second } +
            "sing-box-libbox\u00001.11.4\u0000$nativeDigest").joinToString("\n")
        val inventoryDigest = MessageDigest.getInstance("SHA-256")
            .digest(inventory.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
        val appPackage = linkedMapOf<String, Any>(
            "name" to "Loom Android",
            "SPDXID" to "SPDXRef-Loom-Android",
            "versionInfo" to checkNotNull(android.defaultConfig.versionName),
            "downloadLocation" to "NOASSERTION",
            "filesAnalyzed" to false,
            "licenseConcluded" to "NOASSERTION",
            "licenseDeclared" to "NOASSERTION",
            "copyrightText" to "NOASSERTION",
        )
        val packages = listOf(appPackage, nativePackage) + dependencyRecords.map { it.first }
        val relationships = mutableListOf<Map<String, String>>(
            mapOf(
                "spdxElementId" to "SPDXRef-DOCUMENT",
                "relationshipType" to "DESCRIBES",
                "relatedSpdxElement" to "SPDXRef-Loom-Android",
            ),
        )
        (listOf("SPDXRef-Native-Libbox") + dependencyRecords.map { it.third }).forEach { dependencyID ->
            relationships += mapOf(
                "spdxElementId" to "SPDXRef-Loom-Android",
                "relationshipType" to "DEPENDS_ON",
                "relatedSpdxElement" to dependencyID,
            )
        }
        val created = Instant.ofEpochSecond(
            providers.environmentVariable("SOURCE_DATE_EPOCH").orElse("0").get().toLong(),
        ).toString()
        val document = linkedMapOf<String, Any>(
            "spdxVersion" to "SPDX-2.3",
            "dataLicense" to "CC0-1.0",
            "SPDXID" to "SPDXRef-DOCUMENT",
            "name" to "Loom Android release SBOM",
            "documentNamespace" to "https://github.com/Scisaga/loom/sbom/android/$inventoryDigest",
            "creationInfo" to mapOf(
                "created" to created,
                "creators" to listOf("Tool: Loom Gradle generateAndroidSbom"),
            ),
            "packages" to packages,
            "relationships" to relationships,
        )
        val destination = output.get().asFile
        destination.parentFile.mkdirs()
        destination.writeText(JsonOutput.prettyPrint(JsonOutput.toJson(document)) + "\n")
    }
}
