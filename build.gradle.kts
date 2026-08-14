import com.android.build.gradle.BaseExtension
import com.lagradost.cloudstream3.gradle.CloudstreamExtension
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinJvmCompile

buildscript {
    repositories {
        google()
        mavenCentral()
        // Shitpack repo which contains our tools and dependencies
        maven("https://jitpack.io")
    }

    dependencies {
        classpath("com.android.tools.build:gradle:8.7.3")
        // Cloudstream gradle plugin which makes everything work and builds plugins
        classpath("com.github.recloudstream:gradle:-SNAPSHOT")
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:2.3.0")
    }
}

allprojects {
    repositories {
        google()
        mavenCentral()
        maven("https://jitpack.io")
    }
}

fun Project.cloudstream(configuration: CloudstreamExtension.() -> Unit) = extensions.getByName<CloudstreamExtension>("cloudstream").configuration()

fun Project.android(configuration: BaseExtension.() -> Unit) = extensions.getByName<BaseExtension>("android").configuration()

subprojects {
    apply(plugin = "com.android.library")
    apply(plugin = "kotlin-android")
    apply(plugin = "com.lagradost.cloudstream3.gradle")

    cloudstream {
        // when running through github workflow, GITHUB_REPOSITORY should contain current repository name
        setRepo(System.getenv("GITHUB_REPOSITORY") ?: "Elv0nne/uhnimefourseven")
    }

    android {
        namespace = "com.example"

        defaultConfig {
            minSdk = 21
            compileSdkVersion(35)
            targetSdk = 35
        }

        compileOptions {
            sourceCompatibility = JavaVersion.VERSION_1_8
            targetCompatibility = JavaVersion.VERSION_1_8
        }

        tasks.withType<KotlinJvmCompile> {
            compilerOptions {
                jvmTarget.set(JvmTarget.JVM_1_8) // Required
                freeCompilerArgs.addAll(
                    "-Xno-call-assertions",
                    "-Xno-param-assertions",
                    "-Xno-receiver-assertions"
                )
            }
        }
    }

    dependencies {
        val cloudstream by configurations
        val implementation by configurations

        // Stubs for all cloudstream classes.
        //
        // ĐÃ SỬA: trỏ sang bản fork đã patch (thêm WatchProgressListener vào
        // MainAPI.kt + forward vị trí phát thật trong GeneratorPlayer.kt) thay vì
        // "com.lagradost:cloudstream3:pre-release" chính thức — bản chính thức
        // KHÔNG có interface WatchProgressListener nên biên dịch sẽ lỗi
        // "Unresolved reference 'WatchProgressListener'".
        //
        // XÁC NHẬN THẬT qua JitPack build log (2026-08-14): coordinate
        // "com.github.Elv0nne.cloudstream:library:9b9ae65" build SUCCESSFUL, publish
        // đúng 3 artifact (library, library-jvm, library-android) — dùng thẳng
        // "library" để Gradle/cloudstream plugin tự chọn đúng variant (android/jvm)
        // theo target đang build, không cần chỉ định hậu tố thủ công.
        //
        // Dùng version cố định là commit hash "9b9ae65" (không dùng tag "pre-release"
        // vì tag đó bị MOVE lại mỗi lần push mới lên Elv0nne/cloudstream, không đảm
        // bảo luôn trỏ đúng bản đã build-verify này). Nếu sau này patch thêm code
        // trên fork, thay "9b9ae65" bằng commit hash mới, rồi tự verify lại qua
        // https://jitpack.io/#Elv0nne/cloudstream/<commit-hash> (bấm "Get it", đợi
        // "BUILD SUCCESSFUL") trước khi build plugin, để tránh build lỗi hoặc dùng
        // nhầm bản jitpack cache cũ.
        cloudstream("com.github.Elv0nne.cloudstream:library:9b9ae65")

        // These dependencies can include any of those which are added by the app,
        // but you don't need to include any of them if you don't need them.
        // https://github.com/recloudstream/cloudstream/blob/master/app/build.gradle.kts
        implementation(kotlin("stdlib")) // Adds Standard Kotlin Features
        implementation("com.github.Blatzar:NiceHttp:0.4.11") // HTTP Lib
        implementation("org.jsoup:jsoup:1.18.3") // HTML Parser
        // IMPORTANT: Do not bump Jackson above 2.13.1, as newer versions will
        // break compatibility on older Android devices.
        implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.13.1") // JSON Parser
    }
}

task<Delete>("clean") {
    delete(rootProject.layout.buildDirectory)
}
