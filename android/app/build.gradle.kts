plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.sentinelx.mobile"
    // compileSdk only gates which APIs/libraries can be used; runtime behaviour follows targetSdk (34) below
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        applicationId = "com.sentinelx.mobile"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
        // Emulator/lab rehearsals ONLY: a debuggable build that additionally trusts the local SENTINEL X dev CA
        // (src/rehearsal/res/raw/dev_ca.pem, copied from data/tls/ca.pem). Debug and release builds never include it.
        create("rehearsal") {
            initWith(getByName("debug"))
            matchingFallbacks += "debug"
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        compose = true
    }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2026.02.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.core:core-ktx:1.19.1")
    implementation("androidx.work:work-runtime-ktx:2.10.1")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")   // real org.json for JVM unit tests (the Android stub is a no-op)
}
