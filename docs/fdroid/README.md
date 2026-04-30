# F-Droid preparation

This directory documents the current upstream preparation work for possible
F-Droid inclusion.

## Metadata locations

- Draft fdroiddata YAML: `fdroid/metadata/com.notrus.android.yml`
- Android app metadata: `fastlane/metadata/android/en-US`
- Screenshot directory: `fastlane/metadata/android/en-US/images/phoneScreenshots`

No screenshots are committed yet.

## Build verification

The Android app is expected to build from the command line with:

```bash
cd native/android/NotrusAndroid
./gradlew clean assembleRelease
```

The draft metadata is disabled until a matching public release tag exists and
the fdroiddata signing/build recipe is finalized.

## Dependency audit scope

The Android Gradle configuration currently uses AndroidX, Jetpack Compose,
Material Components, WorkManager, Biometric, desugaring libraries, and Signal
protocol libraries. A repository scan was also run for common proprietary SDK
markers such as Firebase, Google Play Services, ads, analytics, and crash
reporters.

No Firebase, Google Play Services, ads, closed-source analytics SDKs, or
closed-source crash-reporting SDKs were found in the current Android app
configuration.

## Security wording

F-Droid-facing descriptions must remain conservative:

- Do not claim Notrus is secure in an absolute sense.
- Do not claim Notrus is audited unless an external audit actually exists.
- Do not claim anonymity.
- Do explain what the relay can still observe.
- Do explain that attestation enforcement is operator-configured.
