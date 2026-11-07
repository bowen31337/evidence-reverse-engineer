# Android (APK, DEX, JAR)

## With the baseline only
1. `artifact:inventory app.apk --record` lists members by content: `classes*.dex`,
   `lib/<abi>/*.so` (native code: route each to `native.md`), `assets/` (configs, JS for
   React Native/Cordova bundles: route to `javascript-electron.md`), `resources.arsc`, the
   binary `AndroidManifest.xml`.
2. `artifact:extract app.apk --out NEW_DIR --member assets/config.json` and read
   configuration directly. URLs and feature flags are often here.
3. `strings:extract classes.dex` (after extracting) finds class names, URLs and API paths
   quickly, without a decompiler.
4. The manifest is binary AXML. Without apktool, `strings:extract` on it still shows
   permission and component names (as hints, not a parsed manifest).

## With jadx / apktool
- `jadx:decompile app.apk --out NEW_DIR --record`, then read the Java under `sources/`.
  Start from the components declared in the manifest and from the classes that
  `strings` showed.
- `apktool:decode app.apk --out NEW_DIR --record` gives a readable `AndroidManifest.xml`
  (permissions, exported components, deep links) and `res/values/strings.xml`.
- Decompiled Java is a reconstruction. Obfuscated names (a.b.c) are the analyst's
  problem: record renames as inferences.

## When jadx is missing (common)
Don't install it. Record an Unknown: "Java-level logic of <class> requires jadx
(`brew install jadx`)". Give the user the command, and answer what the inventory,
config and strings show, clearly labelled.

## Flutter / React Native / Xamarin
- `lib/*/libflutter.so` + `libapp.so`: Dart AOT. Strings work, full decompilation needs specialised tools (record that as a limitation).
- `assets/index.android.bundle`: React Native JS (Hermes bytecode if it starts with `c6 1f bc 03`).
- `assemblies/*.dll`: Xamarin/.NET. See `managed-dotnet.md`.
