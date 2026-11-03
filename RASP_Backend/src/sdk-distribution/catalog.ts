/**
 * The platform catalog the FE renders as picker cards. `available: false`
 * platforms still render (as "coming soon") but their download endpoint
 * returns 404 — see `routes.ts`.
 *
 * `sourcePath` points at this machine's local `sdk_rasp` checkout for now
 * (honest about it — see the platform plan's "local dev only" scope). A
 * real deployment replaces this with a versioned, published-artifact URL
 * (an internal Maven repo for Android, a pub.dev-style host or git tag for
 * Flutter) rather than zipping source on every download request.
 */
export interface SdkCatalogEntry {
  platform: "ANDROID_NATIVE" | "FLUTTER" | "IOS" | "REACT_NATIVE";
  displayName: string;
  available: boolean;
  minVersion: string;
  minOsVersion: string;
  language: string;
  requirements: string[];
  setupDocsPath: string;
  /** Directories to zip, relative to SDK_SOURCE_ROOT (see .env). */
  sourcePath?: string[];
}

export const SDK_CATALOG: SdkCatalogEntry[] = [
  {
    platform: "ANDROID_NATIVE",
    displayName: "Android (Kotlin / Java)",
    available: true,
    minVersion: "1.1.0",
    minOsVersion: "Android 6.0 (API 23)",
    language: "Kotlin/Java",
    requirements: [
      "minSdk 23+",
      "Kotlin Android Gradle plugin applied (standard in any modern Android Studio project)",
      "INTERNET permission (merges automatically from the SDK's own manifest)",
    ],
    setupDocsPath: "android_native/README.md",
    // android_core is no longer bundled here — rasp_shield_native's own
    // build.gradle.kts now depends on it as a published JitPack artifact
    // (com.github.vgil-DarshanJ:RASP_SDK_1), resolved automatically by
    // Gradle. A consumer needs exactly this one folder, nothing else.
    sourcePath: ["android_native"],
  },
  {
    platform: "FLUTTER",
    displayName: "Flutter",
    available: true,
    minVersion: "1.1.0",
    minOsVersion: "Android 6.0 (API 23) via the plugin's Android side",
    language: "Dart",
    requirements: [
      "Flutter SDK ^3.3.0+",
      "Dart ^3.11.5+",
      "Android minSdk 23+ (this plugin's Android implementation)",
    ],
    setupDocsPath: "flutter/rasp_shield_sdk/docs/LEAN_SECURITY_INTEGRATION_GUIDE.md",
    // android_core used to need to ship alongside `flutter/` here, because
    // the plugin's own android/build.gradle.kts depended on it as a
    // project(":android_core") source-folder reference — which required
    // every consumer to also download android_core AND manually wire it
    // into their own settings.gradle.kts (a real, previously-shipped gap).
    // The plugin now depends on android_core as a published JitPack
    // artifact (com.github.vgil-DarshanJ:RASP_SDK_1) instead, resolved
    // automatically by Gradle — so only `flutter/` needs to ship at all.
    sourcePath: ["flutter"],
  },
  {
    platform: "IOS",
    displayName: "iOS (Swift)",
    available: false,
    minVersion: "not yet released",
    minOsVersion: "TBD",
    language: "Swift",
    requirements: [],
    setupDocsPath: "",
  },
  {
    platform: "REACT_NATIVE",
    displayName: "React Native",
    available: true,
    minVersion: "1.1.0",
    minOsVersion: "Android 7.0 (API 24); iOS not yet supported",
    language: "TypeScript/JavaScript",
    requirements: [
      "React Native 0.76+ (New or Old Architecture)",
      "Android minSdk 24+",
      "Autolinking (standard in any React Native app)",
      "INTERNET permission (merges automatically from the engine's own manifest)",
    ],
    setupDocsPath: "react_native/rasp_shield_react_native/README.md",
    // The plugin binds the same android-core engine (JitPack) as the Flutter
    // plugin; only the plugin folder ships. Its Gradle file adds JitPack itself.
    sourcePath: ["react_native"],
  },
];
