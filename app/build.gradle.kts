import com.android.build.api.variant.HostTestBuilder

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.google.devtools.ksp")
}

val rustPlatformTests = listOf(
    Triple("testRustVpnLifecycle", "lifecycle", "VPN startup, cancellation and network refresh"),
    Triple("testRustPlatformDns", "platform-dns", "Platform DNS completion and cancellation"),
    Triple("testRustConnectionOwner", "connection-owner", "Original TUN connection ownership"),
    Triple("testRustProbePlatforms", "probe-platforms", "Standalone probe sharing and network handover"),
)
rustPlatformTests.forEach { (name, script, summary) ->
    tasks.register<Exec>(name) {
        group = "verification"
        description = "$summary with Android/JNI test boundaries"
        workingDir(rootProject.projectDir)
        environment("AEROBOX_KOTLIN_LIB", gradle.gradleHomeDir!!.resolve("lib").absolutePath)
        environment("JAVA_HOME", System.getProperty("java.home"))
        commandLine("bash", "rust/scripts/test-kotlin-$script.sh")
    }
}
tasks.register("testRustPlatform") {
    group = "verification"
    description = "Run the Kotlin platform boundary regressions"
    dependsOn(rustPlatformTests.map { it.first })
}

val rustAbis = providers.gradleProperty("AEROBOX_ABIS").orElse("arm64-v8a,armeabi-v7a,x86_64,x86")
    .get().split(',').map(String::trim).distinct()
require(rustAbis.isNotEmpty() && rustAbis.all { it in setOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86") }) {
    "AEROBOX_ABIS must contain supported Android ABIs separated by commas"
}
val rustProfile = providers.gradleProperty("AEROBOX_RUST_PROFILE").orElse("release")
require(rustProfile.get() in setOf("release", "dev")) { "AEROBOX_RUST_PROFILE must be release or dev" }
val rustJniDirectory = layout.buildDirectory.dir("generated/rust/jniLibs")
abstract class RustNativeBuild : Exec() {
    @get:OutputDirectory
    abstract val jniDirectory: DirectoryProperty
}

val buildRustNative = tasks.register<RustNativeBuild>("buildRustNative") {
    group = "build"
    description = "Build the in-repository Rust JNI library for the selected Android ABIs"
    workingDir(rootProject.file("rust"))
    inputs.files(rootProject.fileTree("rust") {
        exclude("**/target/**", "**/.git/**", "**/build/**", "**/*.md")
        // Host tests and fixtures do not participate in the Android library.
        exclude("docs/**", "tests/**", "android/tests/**", "scripts/test-*.sh")
        exclude("crates/*/tests/**", "crates/*/validation/**")
        exclude("vendor/shoes/tests/**", "vendor/shoes/benches/**", "vendor/shoes/examples/**", "vendor/shoes/scripts/**")
    })
    inputs.property("abis", rustAbis)
    inputs.property("profile", rustProfile)
    jniDirectory.set(rustJniDirectory)
    doFirst { jniDirectory.get().asFile.deleteRecursively() }
    environment("AEROBOX_JNI_DIR", rustJniDirectory.get().asFile.absolutePath)
    environment("AEROBOX_BUILD_PROFILE", rustProfile.get())
    environment("ANDROID_API_LEVEL", "31")
    commandLine("bash", "android/build.sh", *rustAbis.toTypedArray())
}

android {
    namespace = "com.aerobox"
    compileSdk = 37
    compileSdkMinor = 2
    ndkVersion = "30.0.16248370"

    val ciVersionName = (project.findProperty("AEROBOX_VERSION_NAME") as? String)?.trim()
    val ciVersionCode = (project.findProperty("AEROBOX_VERSION_CODE") as? String)
        ?.toIntOrNull()
    defaultConfig {
        applicationId = "com.aerobox"
        minSdk = 31
        targetSdk = 37
        versionCode = ciVersionCode ?: 1
        versionName = ciVersionName ?: "1.0.0"

    }

    androidResources {
        // Restrict packaged locales to those we actually translate. Without
        // this filter, every androidx / Compose / Material3 / WorkManager
        // artifact contributes its own localized strings (~50 locales) to the
        // APK. Default fallback (values/strings.xml) is English; system
        // languages outside this list will fall back to English rather than
        // Simplified Chinese.
        localeFilters += listOf("en", "zh-rCN", "zh-rTW", "fa", "ru")
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            isMinifyEnabled = false
        }
        create("beta") {
            initWith(getByName("release"))
            matchingFallbacks += listOf("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_25
        targetCompatibility = JavaVersion.VERSION_25
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    splits {
        abi {
            isEnable = true
            reset()
            include(*rustAbis.toTypedArray())
            isUniversalApk = false
        }
    }

    bundle {
        language {
            enableSplit = false
        }
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true // compress .so inside APK to reduce sideload APK size
        }
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "DebugProbesKt.bin"
            excludes += "kotlin-tooling-metadata.json"
            // Multi-release jar duplicates and JVM-only metadata that Android
            // never reads at runtime. Cheap, lossless trim.
            excludes += "/META-INF/versions/9/**"
            excludes += "/META-INF/*.kotlin_module"
            excludes += "/META-INF/INDEX.LIST"
            excludes += "/META-INF/io.netty.versions.properties"
            excludes += "/META-INF/native-image/**"
        }
    }
}

androidComponents {
    onVariants(selector().all()) { variant ->
        variant.sources.jniLibs?.addGeneratedSourceDirectory(buildRustNative, RustNativeBuild::jniDirectory)
    }
    beforeVariants(selector().all()) { variantBuilder ->
        variantBuilder.enableAndroidTest = false
        variantBuilder.hostTests[HostTestBuilder.UNIT_TEST_TYPE]?.enable = variantBuilder.buildType == "debug"
    }
}

tasks.withType<Test>().configureEach {
    systemProperty("aerobox.schemaDirectory", layout.projectDirectory.dir("schemas").asFile.absolutePath)
    maxHeapSize = "512m"
    maxParallelForks = 1
    jvmArgs("-XX:ActiveProcessorCount=3")
}

ksp {
    arg("room.schemaLocation", "$projectDir/schemas")
}

dependencies {
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
    testImplementation("org.json:json:20260814")

    implementation("androidx.core:core-ktx:1.19.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.11.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.0")
    implementation("androidx.activity:activity-compose:1.13.0")

    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-core")
    // material-icons-extended remains removed to avoid pulling the full icon set

    implementation("androidx.navigation:navigation-compose:2.10.2")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.11.0")
    implementation("androidx.work:work-runtime-ktx:2.12.0")

    implementation("androidx.room:room-runtime:2.8.5")
    implementation("androidx.room:room-ktx:2.8.5")
    ksp("androidx.room:room-compiler:2.8.5")

    implementation("androidx.datastore:datastore-preferences:1.3.0")

    implementation("com.squareup.okhttp3:okhttp:5.5.1")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    implementation("org.yaml:snakeyaml:2.7")
    implementation("org.tukaani:xz:1.12")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")

    implementation("com.google.accompanist:accompanist-drawablepainter:0.37.3")
}
