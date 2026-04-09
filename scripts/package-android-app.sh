#!/bin/zsh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT_DIR="$ROOT_DIR/native/android/NotrusAndroid"
ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}"
JAVA_HOME="${JAVA_HOME:-/Applications/Android Studio.app/Contents/jbr/Contents/Home}"
GRADLE_USER_HOME="${GRADLE_USER_HOME:-$ROOT_DIR/.build/gradle-home/android}"

if [[ ! -d "$ANDROID_SDK_ROOT" ]]; then
  echo "Android SDK not found at $ANDROID_SDK_ROOT" >&2
  exit 1
fi

if [[ ! -d "$JAVA_HOME" ]]; then
  echo "Android Studio runtime not found at $JAVA_HOME" >&2
  exit 1
fi

cd "$PROJECT_DIR"
mkdir -p "$GRADLE_USER_HOME"
export ANDROID_SDK_ROOT JAVA_HOME GRADLE_USER_HOME
./gradlew assembleDebug assembleRelease

DIST_DIR="$ROOT_DIR/dist/android"
mkdir -p "$DIST_DIR"

rm -f \
  "$DIST_DIR/NotrusAndroid-debug.apk" \
  "$DIST_DIR/NotrusAndroid-debug.apk.sha256" \
  "$DIST_DIR/NotrusAndroid-release.apk" \
  "$DIST_DIR/NotrusAndroid-release.apk.sha256" \
  "$DIST_DIR/NotrusAndroid-release-unsigned.apk" \
  "$DIST_DIR/NotrusAndroid-release-unsigned.apk.sha256"

DEBUG_APK="$PROJECT_DIR/app/build/outputs/apk/debug/app-debug.apk"
SIGNED_RELEASE_APK="$PROJECT_DIR/app/build/outputs/apk/release/app-release.apk"
RELEASE_LABEL="release"
RELEASE_APK="$SIGNED_RELEASE_APK"

if [[ ! -f "$SIGNED_RELEASE_APK" ]]; then
  echo "Signed release APK not found at $SIGNED_RELEASE_APK" >&2
  exit 1
fi

cp "$DEBUG_APK" "$DIST_DIR/NotrusAndroid-debug.apk"
cp "$RELEASE_APK" "$DIST_DIR/NotrusAndroid-$RELEASE_LABEL.apk"

shasum -a 256 "$DIST_DIR/NotrusAndroid-debug.apk" > "$DIST_DIR/NotrusAndroid-debug.apk.sha256"
shasum -a 256 "$DIST_DIR/NotrusAndroid-$RELEASE_LABEL.apk" > "$DIST_DIR/NotrusAndroid-$RELEASE_LABEL.apk.sha256"
