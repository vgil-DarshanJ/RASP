"use client";

import { useEffect, useMemo, useState } from "react";
import { apiFetch } from "@/lib/api-client";
import {
  AndroidLogo,
  AppleLogo,
  BookOpenIcon,
  Card,
  CategoryChip,
  FlutterLogo,
  ReactLogo,
} from "@/components/ui";
import { CATEGORY_COLORS, catalogFor } from "@/lib/alertCatalog";
import { DETECTOR_GUIDE } from "@/lib/integrationGuide";

interface SdkCatalogEntry {
  platform: "ANDROID_NATIVE" | "FLUTTER" | "IOS" | "REACT_NATIVE";
  displayName: string;
  available: boolean;
  minVersion: string;
  minOsVersion: string;
  language: string;
  requirements: string[];
}

const PLATFORM_LOGOS: Record<string, (p: { size?: number; className?: string }) => React.ReactNode> = {
  ANDROID_NATIVE: AndroidLogo,
  FLUTTER: FlutterLogo,
  IOS: AppleLogo,
  REACT_NATIVE: ReactLogo,
};

function CodeBlock({ children }: { children: string }) {
  return (
    <pre className="overflow-x-auto rounded-xl bg-ink-950 p-4 font-mono text-xs leading-relaxed text-ink-100">
      {children}
    </pre>
  );
}

function flutterSteps(): { title: string; body: React.ReactNode }[] {
  return [
    {
      title: "1. Add the JitPack repository to your app (not the SDK's files — yours)",
      body: (
        <div className="space-y-2 text-sm text-ink-600">
          <p>
            The SDK&apos;s detection engine is published via{" "}
            <a href="https://jitpack.io" target="_blank" rel="noreferrer" className="font-medium text-brand-700 hover:underline">
              JitPack
            </a>{" "}
            — Gradle fetches it automatically, but only once it knows where to look. Open{" "}
            <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">android/build.gradle.kts</code> in your
            Flutter app and add one line to the <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">repositories</code>{" "}
            block every fresh project already has:
          </p>
          <CodeBlock>{`allprojects {
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }   // ← add this line
    }
}`}</CodeBlock>
          <p className="text-xs text-ink-500">
            If your project instead has a <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">dependencyResolutionManagement</code>{" "}
            block in <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">android/settings.gradle.kts</code>, add the same
            line inside that block instead — same one line, different file. Skipping this step produces a clear
            &quot;could not resolve&quot; Gradle error, never a silent failure.
          </p>
        </div>
      ),
    },
    {
      title: "2. Add the SDK dependency and a place for your credential",
      body: (
        <div className="space-y-2 text-sm text-ink-600">
          <p>
            Download the SDK from the <a href="/apps" className="font-medium text-brand-700 hover:underline">Applications</a> page,
            unzip it, then add it to <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">pubspec.yaml</code>:
          </p>
          <CodeBlock>{`dependencies:
  flutter:
    sdk: flutter
  rasp_shield:
    path: ../rasp_shield_flutter_sdk/flutter/rasp_shield_sdk   # ← add this`}</CodeBlock>
          <p>
            Then, in the <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">flutter:</code> block further down the
            same file, register an asset for your credential:
          </p>
          <CodeBlock>{`flutter:
  uses-material-design: true
  assets:
    - assets/rasp_credential.json   # ← add this`}</CodeBlock>
          <p>
            Create an <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">assets/</code> folder at your project root
            and put the credential.json you downloaded there, renamed to exactly{" "}
            <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">rasp_credential.json</code>. Then run{" "}
            <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">flutter pub get</code>.
          </p>
        </div>
      ),
    },
    {
      title: "3. Wire it into your app's startup — the only code you write",
      body: (
        <div className="space-y-2 text-sm text-ink-600">
          <p>
            In your main screen&apos;s <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">State</code> class —
            everything marked <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">← add</code> is new, the rest is
            what a fresh Flutter project already has:
          </p>
          <CodeBlock>{`import 'package:flutter/services.dart' show rootBundle;                 // ← add
import 'package:rasp_shield/sdk/events/security_event_shipper.dart';    // ← add
import 'package:rasp_shield/sdk/lean_session.dart';                     // ← add

class _MyHomePageState extends State<MyHomePage> {
  RaspLeanSession? _raspSession;                                        // ← add

  @override
  void initState() {
    super.initState();
    _bootstrapRasp();                                                   // ← add
  }

  Future<void> _bootstrapRasp() async {                                 // ← add this whole method
    final restored = await RaspSecurityEventShipper.restore();
    if (!restored) {
      final credentialJson = await rootBundle.loadString('assets/rasp_credential.json');
      await RaspSecurityEventShipper.configureAndPersist(credentialJson);
    }

    _raspSession = await RaspLeanSession.start(const RaspLeanConfig(
      screenshotProtection: true,
      usbDetection: true,
      adbDetection: true,
      rootDetection: true,
      fridaDetection: true,
      hookDetection: true,
      mitmDetection: true,
      // ...enable any of the other detectors in the matrix below
    ));

    _raspSession!.stateStream.listen((state) {
      final root = state.extendedDetectors['root_jailbreak'];
      if (root != null && root.status.isThreat) {
        // your policy: block a payment screen, log the user out, etc.
      }
    });
  }

  @override
  void dispose() {                                                      // ← add this whole method
    _raspSession?.dispose();
    super.dispose();
  }
}`}</CodeBlock>
        </div>
      ),
    },
    {
      title: "4. Optional — supply location (the SDK never fetches it itself)",
      body: (
        <CodeBlock>{`session.currentLocation = RaspLocationSnapshot(
  latitude: lat,
  longitude: lng,
  capturedAt: DateTime.now().toUtc(),
);`}</CodeBlock>
      ),
    },
  ];
}

function androidNativeSteps(): { title: string; body: React.ReactNode }[] {
  return [
    {
      title: "1. Add the JitPack repository to your app (not the SDK's files — yours)",
      body: (
        <div className="space-y-2 text-sm text-ink-600">
          <p>
            The detection engine (<code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">android_core</code>) is
            published via{" "}
            <a href="https://jitpack.io" target="_blank" rel="noreferrer" className="font-medium text-brand-700 hover:underline">
              JitPack
            </a>{" "}
            rather than bundled as source you copy in — Gradle fetches it automatically once it knows where to look. Open
            your app's root <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">build.gradle.kts</code> and add
            one line to the existing repositories block:
          </p>
          <CodeBlock>{`// build.gradle.kts — your app, BEFORE
allprojects {
    repositories {
        google()
        mavenCentral()
    }
}`}</CodeBlock>
          <CodeBlock>{`// build.gradle.kts — your app, AFTER
allprojects {
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }   // ← add this line
    }
}`}</CodeBlock>
          <p className="text-xs text-ink-500">
            If your project instead centralizes repositories in{" "}
            <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">settings.gradle.kts</code> under a{" "}
            <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">dependencyResolutionManagement</code> block,
            add the same line there instead — same one line, different file. Skipping this step produces a clear, specific
            &quot;could not resolve com.github.Vedant0Nisar:RaShield-SDK&quot; error at build time, never a silent failure.
          </p>
        </div>
      ),
    },
    {
      title: "2. Add the module to your project",
      body: (
        <div className="space-y-2 text-sm text-ink-600">
          <p>
            Download the SDK from the <a href="/apps" className="font-medium text-brand-700 hover:underline">Applications</a>{" "}
            page and unzip it so <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">rasp_shield_native</code>{" "}
            sits alongside your app. Then, in <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">settings.gradle.kts</code>,
            add the include — this is the <strong>only</strong> module you need now; <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">android_core</code>{" "}
            is resolved automatically via the repository you just added, not as a local module:
          </p>
          <CodeBlock>{`// settings.gradle.kts
include(":rasp_shield_native")
project(":rasp_shield_native").projectDir =
    File(rootDir, "rasp_shield/rasp_shield_native")`}</CodeBlock>
          <p>And depend on it from your app module:</p>
          <CodeBlock>{`// app/build.gradle.kts
dependencies {
    implementation(project(":rasp_shield_native"))
}`}</CodeBlock>
        </div>
      ),
    },
    {
      title: "3. Wire it into your app's startup — the only code you write",
      body: (
        <div className="space-y-2 text-sm text-ink-600">
          <p>
            In your <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">Application</code> subclass —
            everything marked <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">← add</code> is new:
          </p>
          <CodeBlock>{`// YourApplication.kt
import com.shieldsdk.rasp.RaspEventShipper                              // ← add
import com.shieldsdk.rasp.nativeshield.RaspLeanSession                  // ← add
import com.shieldsdk.rasp.nativeshield.RaspLeanConfig                   // ← add

class YourApplication : Application() {
    override fun onCreate() {
        super.onCreate()

        // First launch ever: paste your downloaded credential.json below.
        // Every launch after that, restore() reads it back automatically.
        if (!RaspEventShipper.restore(applicationContext)) {
            val credentialJson = """<paste your downloaded credential.json contents here>"""
            RaspEventShipper.configureAndPersist(applicationContext, credentialJson)
        }

        // Starts the background poll/ship loop — the only place you
        // choose which of the 42 detectors are active.
        RaspLeanSession.start(
            context = applicationContext,
            config = RaspLeanConfig(
                screenshotProtection = true,
                usbDetection = true,
                adbDetection = true,
                rootDetection = true,
                fridaDetection = true,
                hookDetection = true,
                mitmDetection = true,
                // ...enable any of the other detectors in the matrix below
            ),
        )
    }
}`}</CodeBlock>
          <p>
            If you want screenshot protection to actually apply (it needs a live{" "}
            <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">Activity</code>, not just a{" "}
            <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">Context</code>), pass{" "}
            <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">activityProvider</code> from whichever Activity
            is in the foreground, and react to live state the same way:
          </p>
          <CodeBlock>{`// TransferActivity.kt — a screen showing sensitive data
class TransferActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val session = RaspLeanSession.start(
            context = applicationContext,
            config = RaspLeanConfig(screenshotProtection = true /* ...plus whatever else */),
            activityProvider = { this },   // ← lets FLAG_SECURE actually apply here
        )

        session.setListener { state ->
            val root = state.extendedDetectors["root_jailbreak"]
            if (root?.status?.isThreat == true) {
                // your policy: finish() this Activity, force logout, etc.
            }
        }
    }
}`}</CodeBlock>
          <p className="text-xs text-ink-500">
            Register your <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">Application</code> subclass in{" "}
            <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">AndroidManifest.xml</code> (
            <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">android:name=&quot;.YourApplication&quot;</code>{" "}
            on the <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">&lt;application&gt;</code> tag) if you
            haven't already.
          </p>
        </div>
      ),
    },
    {
      title: "4. Optional — supply location (the SDK never fetches it itself)",
      body: (
        <CodeBlock>{`session.currentLocation = RaspLocationSnapshot(
    latitude = lat,
    longitude = lng,
    capturedAtMillis = System.currentTimeMillis(),
)`}</CodeBlock>
      ),
    },
  ];
}

function reactNativeSteps(): { title: string; body: React.ReactNode }[] {
  return [
    {
      title: "1. Add the plugin to your app",
      body: (
        <div className="space-y-2 text-sm text-ink-600">
          <p>
            Unzip the downloaded SDK next to your app and install the{" "}
            <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">rasp_shield_react_native</code> folder as a
            local dependency. React Native autolinks it; the detection engine comes from JitPack, which the plugin adds to
            Gradle for you.
          </p>
          <CodeBlock>{`npm install ../rasp-shield-react-native/react_native/rasp_shield_react_native
# then rebuild the Android app`}</CodeBlock>
        </div>
      ),
    },
    {
      title: "2. Declare the permissions your detectors need",
      body: (
        <div className="space-y-2 text-sm text-ink-600">
          <p>
            Add only what you use to <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">AndroidManifest.xml</code>:
            READ_PHONE_STATE (SIM change, call during app use), DETECT_SCREEN_CAPTURE (screenshot event),
            DETECT_SCREEN_RECORDING (screen recording), ACCESS_WIFI_STATE and ACCESS_NETWORK_STATE (unsafe Wi-Fi).
          </p>
        </div>
      ),
    },
    {
      title: "3. Save the credential and start a session",
      body: (
        <div className="space-y-2 text-sm text-ink-600">
          <p>
            Paste the <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">credential.json</code> you downloaded
            for this application. The secret stays in encrypted native storage and never returns to JavaScript. Config field
            names match the Kotlin column in the table below.
          </p>
          <CodeBlock>{`import { RaspEventShipper, configFromDetectors, useRaspSession } from "rasp-shield-react-native";

await RaspEventShipper.configure(credentialJson, { persist: true });

const config = configFromDetectors(["root_jailbreak", "frida", "hook_detection", "vpn"], {
  expectedSigningCertSha256: "<your release certificate SHA-256>",
});

// In a component:
const { state } = useRaspSession(config);
state.extendedDetectors.root_jailbreak?.status; // SECURE | DETECTED | UNAVAILABLE | UNKNOWN | ERROR`}</CodeBlock>
        </div>
      ),
    },
    {
      title: "4. Read results honestly",
      body: (
        <p className="text-sm text-ink-600">
          Only DETECTED is a threat and only SECURE is a pass. UNAVAILABLE, UNKNOWN and ERROR mean the check could not
          reach a verdict. iOS is not supported yet; there every detector reports UNAVAILABLE.
        </p>
      ),
    },
    {
      title: "5. Check your release build",
      body: (
        <div className="space-y-2 text-sm text-ink-600">
          <p>
            If your backend URL is plain HTTP (office or test servers), add a{" "}
            <code className="rounded bg-ink-100 px-1 py-0.5 font-mono text-xs">network_security_config</code> that allows
            it; HTTPS needs nothing. Then run a self-test on the release build (for example in CI) to catch R8/ProGuard
            stripping the engine.
          </p>
          <CodeBlock>{`import { RaspShieldCore } from "rasp-shield-react-native";

const report = await RaspShieldCore.selfTest();`}</CodeBlock>
        </div>
      ),
    },
  ];
}

/**
 * Per-platform setup guide + the full 26-detector support matrix — what
 * you get, the exact `RaspLeanConfig` field to flip on, and (the
 * question every reviewer asks) what actually goes wrong if you leave it
 * off. Platform availability is read live from `/v1/sdk/catalog` (the
 * same data the Applications page's download cards use) rather than
 * hardcoded here, so iOS/React Native only ever show as available the
 * moment a real SDK exists for them.
 */
export default function IntegrationGuidePage() {
  const [platforms, setPlatforms] = useState<SdkCatalogEntry[] | null>(null);
  const [selected, setSelected] = useState<"FLUTTER" | "ANDROID_NATIVE" | "REACT_NATIVE">("FLUTTER");

  useEffect(() => {
    apiFetch<{ platforms: SdkCatalogEntry[] }>("/v1/sdk/catalog").then((res) => setPlatforms(res.platforms));
  }, []);

  const steps = useMemo(
    () => (selected === "FLUTTER" ? flutterSteps() : selected === "REACT_NATIVE" ? reactNativeSteps() : androidNativeSteps()),
    [selected],
  );

  const matrixRows = useMemo(
    () =>
      DETECTOR_GUIDE.map((g) => ({
        ...g,
        catalog: catalogFor(g.detectorId),
        field: selected === "FLUTTER" ? g.dartField : g.kotlinField,
      })),
    [selected],
  );

  if (!platforms) {
    return (
      <div className="animate-pulse space-y-6">
        <div className="h-8 w-64 rounded-lg bg-ink-100" />
        <div className="h-40 rounded-2xl bg-ink-100" />
        <div className="h-96 rounded-2xl bg-ink-100" />
      </div>
    );
  }

  return (
    <div>
      <div className="mb-6">
        <h1 className="flex items-center gap-2 text-2xl font-semibold text-ink-900">
          <BookOpenIcon size={22} className="text-brand-600" />
          Integration Guide
        </h1>
        <p className="mt-1 text-sm text-ink-500">
          Every detector the SDK ships, which platforms support it, how to turn it on, and what you're
          exposed to if you don't.
        </p>
      </div>

      <div className="mb-6 flex flex-wrap gap-2">
        {platforms.map((p) => {
          const Logo = PLATFORM_LOGOS[p.platform] ?? AndroidLogo;
          const isSelectable = p.available && (p.platform === "FLUTTER" || p.platform === "ANDROID_NATIVE" || p.platform === "REACT_NATIVE");
          const active = selected === p.platform;
          return (
            <button
              key={p.platform}
              disabled={!isSelectable}
              onClick={() => isSelectable && setSelected(p.platform as "FLUTTER" | "ANDROID_NATIVE" | "REACT_NATIVE")}
              className={`flex items-center gap-2 rounded-xl border px-4 py-3 text-sm font-medium transition ${
                active
                  ? "border-brand-300 bg-brand-50 text-brand-800 ring-1 ring-brand-200"
                  : isSelectable
                  ? "border-ink-200 bg-surface text-ink-700 hover:border-brand-200 hover:bg-brand-50/40"
                  : "cursor-not-allowed border-ink-100 bg-ink-50 text-ink-400"
              }`}
            >
              <Logo size={18} />
              {p.displayName}
              {!p.available && <span className="text-xs font-normal text-ink-400">· coming soon</span>}
            </button>
          );
        })}
      </div>

      <Card className="mb-6 p-6">
        <h2 className="mb-4 text-sm font-semibold text-ink-700">
          Setup — {platforms.find((p) => p.platform === selected)?.displayName}
        </h2>
        <div className="space-y-5">
          {steps.map((step) => (
            <div key={step.title}>
              <h3 className="mb-2 text-sm font-medium text-ink-800">{step.title}</h3>
              {step.body}
            </div>
          ))}
        </div>
      </Card>

      <Card className="overflow-hidden">
        <div className="border-b border-ink-100 px-5 py-4">
          <h2 className="text-sm font-semibold text-ink-700">Full detector support matrix — {DETECTOR_GUIDE.length} detectors</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-ink-100 text-xs uppercase tracking-wide text-ink-400">
                <th className="py-2.5 pl-5 pr-4 font-medium">Detector</th>
                <th className="py-2.5 pr-4 font-medium">Category</th>
                <th className="py-2.5 pr-4 font-medium">Severity</th>
                <th className="py-2.5 pr-4 font-medium">Config field to enable</th>
                <th className="py-2.5 pr-5 font-medium">If you don't enable it</th>
              </tr>
            </thead>
            <tbody>
              {matrixRows.map((row) => {
                const colors = CATEGORY_COLORS[row.catalog.category];
                return (
                  <tr key={row.detectorId} className="border-b border-ink-50 align-top">
                    <td className="py-3 pl-5 pr-4">
                      <div className="font-medium text-ink-900">{row.catalog.title}</div>
                      <div className="font-mono text-[11px] text-ink-400">{row.detectorId}</div>
                    </td>
                    <td className="py-3 pr-4">
                      <CategoryChip label={row.catalog.category} colors={colors} />
                    </td>
                    <td className="py-3 pr-4">
                      <span className="text-xs font-medium capitalize text-ink-700">{row.catalog.severity}</span>
                    </td>
                    <td className="py-3 pr-4">
                      {row.backendRule ? (
                        <span className="text-xs text-ink-600">Backend rule: send {row.field}</span>
                      ) : (
                        <code className="rounded bg-ink-100 px-1.5 py-0.5 font-mono text-xs text-ink-800">
                          {row.field}: true
                        </code>
                      )}
                    </td>
                    <td className="max-w-md py-3 pr-5 text-xs leading-relaxed text-ink-600">
                      {row.consequenceIfDisabled}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
