plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

@Suppress("UnstableApiUsage")

val signalVersion = "0.93.1"
val defaultRelayOrigin = System.getenv("NOTRUS_DEFAULT_RELAY_ORIGIN") ?: "https://ramal-paola-yolky.ngrok-free.dev"
val releaseKeystorePath = System.getenv("NOTRUS_ANDROID_KEYSTORE_PATH")
val releaseKeystorePassword = System.getenv("NOTRUS_ANDROID_KEYSTORE_PASSWORD")
val releaseKeyAlias = System.getenv("NOTRUS_ANDROID_KEY_ALIAS")
val releaseKeyPassword = System.getenv("NOTRUS_ANDROID_KEY_PASSWORD")
val releaseMode = (System.getenv("NOTRUS_RELEASE_MODE") ?: "local").lowercase()
val notrusVersionName = System.getenv("NOTRUS_ANDROID_VERSION") ?: "0.3.4-beta5"
val notrusBuildCounter = System.getenv("NOTRUS_ANDROID_BUILD_COUNTER") ?: "dev"
val notrusBuildId = System.getenv("NOTRUS_ANDROID_BUILD_ID") ?: "${notrusVersionName}+android.dev"
val enforceProductionSigning = releaseMode == "production"
val playIntegrityCloudProjectNumber =
    (System.getenv("NOTRUS_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER") ?: "0").toLongOrNull() ?: 0L
val hasReleaseSigning =
    !releaseKeystorePath.isNullOrBlank() &&
        !releaseKeystorePassword.isNullOrBlank() &&
        !releaseKeyAlias.isNullOrBlank() &&
        !releaseKeyPassword.isNullOrBlank()

android {
    namespace = "com.notrus.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.notrus.android"
        minSdk = 31
        targetSdk = 35
        versionCode = 7
        versionName = notrusVersionName
        buildConfigField("String", "DEFAULT_RELAY_ORIGIN", "\"$defaultRelayOrigin\"")
        buildConfigField("String", "NOTRUS_BUILD_COUNTER", "\"$notrusBuildCounter\"")
        buildConfigField("String", "NOTRUS_BUILD_ID", "\"$notrusBuildId\"")
        buildConfigField("long", "PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER", "${playIntegrityCloudProjectNumber}L")
        ndk {
            abiFilters += listOf("arm64-v8a")
        }

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables {
            useSupportLibrary = true
        }
    }

    signingConfigs {
        if (hasReleaseSigning) {
            create("release") {
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
                storeFile = file(requireNotNull(releaseKeystorePath))
                storePassword = releaseKeystorePassword
            }
        }
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            if (hasReleaseSigning) {
                signingConfig = signingConfigs.getByName("release")
            } else if (enforceProductionSigning) {
                throw GradleException(
                    "Production Android releases require NOTRUS_ANDROID_KEYSTORE_PATH, NOTRUS_ANDROID_KEYSTORE_PASSWORD, NOTRUS_ANDROID_KEY_ALIAS, and NOTRUS_ANDROID_KEY_PASSWORD."
                )
            } else {
                signingConfig = signingConfigs.getByName("debug")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        isCoreLibraryDesugaringEnabled = true
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        jniLibs {
            excludes += setOf(
                "**/libsignal_jni_testing.so",
                "**/libsignal_jni*.dylib",
                "**/signal_jni*.dll",
            )
        }
        resources {
            excludes += setOf(
                "/META-INF/{AL2.0,LGPL2.1}",
                "**/*.dylib",
                "**/*.dll",
            )
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
        freeCompilerArgs.add("-jvm-default=enable")
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.06.00")

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.activity:activity-compose:1.9.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.4")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.4")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.10.0")
    implementation("androidx.work:work-runtime-ktx:2.11.2")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("org.signal:libsignal-client:$signalVersion")
    implementation("org.signal:libsignal-android:$signalVersion")
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.5")

    implementation(composeBom)
    androidTestImplementation(composeBom)

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.animation:animation")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")

    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")

    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.6.1")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    testImplementation("junit:junit:4.13.2")
}
