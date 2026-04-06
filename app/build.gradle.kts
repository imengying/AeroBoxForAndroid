plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.google.devtools.ksp")
}

android {
    namespace = "com.aerobox"
    compileSdk = 36
    compileSdkMinor = 1

    val ciVersionName = (project.findProperty("AEROBOX_VERSION_NAME") as? String)?.trim()
    val ciVersionCode = (project.findProperty("AEROBOX_VERSION_CODE") as? String)
        ?.toIntOrNull()
    val configuredAbis = ((project.findProperty("AEROBOX_ABIS") as? String)
        ?.split(',')
        ?.map { it.trim() }
        ?.filter { it.isNotEmpty() })
        ?.takeIf { it.isNotEmpty() }
        ?: listOf("armeabi-v7a", "arm64-v8a", "x86", "x86_64")

    defaultConfig {
        applicationId = "com.aerobox"
        minSdk = 31
        targetSdk = 36
        versionCode = ciVersionCode ?: 1
        versionName = ciVersionName ?: "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
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
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    splits {
        abi {
            isEnable = true
            reset()
            include(*configuredAbis.toTypedArray())
            isUniversalApk = false
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
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.18.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.10.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.10.0")
    implementation("androidx.activity:activity-compose:1.13.0")

    implementation(platform("androidx.compose:compose-bom:2026.03.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-core")
    // material-icons-extended remains removed to avoid pulling the full icon set

    implementation("androidx.navigation:navigation-compose:2.9.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.10.0")
    implementation("androidx.work:work-runtime-ktx:2.11.1")

    implementation("androidx.room:room-runtime:2.8.4")
    implementation("androidx.room:room-ktx:2.8.4")
    ksp("androidx.room:room-compiler:2.8.4")

    implementation("androidx.datastore:datastore-preferences:1.2.1")

    implementation("com.squareup.okhttp3:okhttp:5.3.2")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    implementation("org.yaml:snakeyaml:2.6")
    implementation("org.tukaani:xz:1.12")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")

    implementation(files(layout.buildDirectory.file("libbox/libbox.aar")))

    implementation("com.google.accompanist:accompanist-drawablepainter:0.37.3")

    debugImplementation("androidx.compose.ui:ui-tooling")
}
