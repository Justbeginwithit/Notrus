#!/bin/zsh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT_DIR="$ROOT_DIR/native/android/NotrusAndroid"
APP_VERSION="${NOTRUS_ANDROID_VERSION:-0.3.1-beta2}"
ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}"
JAVA_HOME="${JAVA_HOME:-/Applications/Android Studio.app/Contents/jbr/Contents/Home}"
GRADLE_USER_HOME="${GRADLE_USER_HOME:-$ROOT_DIR/.build/gradle-home/android}"
RELEASE_MODE="${NOTRUS_RELEASE_MODE:-local}"
RELEASE_APPROVALS_PATH="${NOTRUS_RELEASE_APPROVALS_PATH:-$ROOT_DIR/config/release/approvals.json}"
RELEASE_KEYSTORE_PATH="${NOTRUS_ANDROID_KEYSTORE_PATH:-}"
RELEASE_KEYSTORE_PASSWORD="${NOTRUS_ANDROID_KEYSTORE_PASSWORD:-}"
RELEASE_KEY_ALIAS="${NOTRUS_ANDROID_KEY_ALIAS:-}"
RELEASE_KEY_PASSWORD="${NOTRUS_ANDROID_KEY_PASSWORD:-}"

if [[ ! -d "$ANDROID_SDK_ROOT" ]]; then
  echo "Android SDK not found at $ANDROID_SDK_ROOT" >&2
  exit 1
fi

if [[ ! -d "$JAVA_HOME" ]]; then
  echo "Android Studio runtime not found at $JAVA_HOME" >&2
  exit 1
fi

if [[ "$RELEASE_MODE" == "production" ]]; then
  NOTRUS_RELEASE_MODE="$RELEASE_MODE" \
  NOTRUS_RELEASE_APPROVALS_PATH="$RELEASE_APPROVALS_PATH" \
  node "$ROOT_DIR/scripts/verify-release-governance.mjs"

  if [[ -z "$RELEASE_KEYSTORE_PATH" || -z "$RELEASE_KEYSTORE_PASSWORD" || -z "$RELEASE_KEY_ALIAS" || -z "$RELEASE_KEY_PASSWORD" ]]; then
    echo "Production Android releases require NOTRUS_ANDROID_KEYSTORE_PATH, NOTRUS_ANDROID_KEYSTORE_PASSWORD, NOTRUS_ANDROID_KEY_ALIAS, and NOTRUS_ANDROID_KEY_PASSWORD." >&2
    exit 1
  fi

  if [[ ! -f "$RELEASE_KEYSTORE_PATH" ]]; then
    echo "Production Android keystore was not found at $RELEASE_KEYSTORE_PATH." >&2
    exit 1
  fi

  case "$RELEASE_KEYSTORE_PATH" in
    "$ROOT_DIR"/*)
      echo "Production Android keystores must not live inside the repository workspace." >&2
      exit 1
      ;;
  esac
fi

cd "$PROJECT_DIR"
mkdir -p "$GRADLE_USER_HOME"
export ANDROID_SDK_ROOT JAVA_HOME GRADLE_USER_HOME NOTRUS_RELEASE_MODE
./gradlew assembleDebug assembleRelease

DIST_DIR="$ROOT_DIR/dist/android"
mkdir -p "$DIST_DIR"

APK_BASENAME="Notrus"

rm -f \
  "$DIST_DIR/$APK_BASENAME-debug.apk" \
  "$DIST_DIR/$APK_BASENAME-debug.apk.sha256" \
  "$DIST_DIR/$APK_BASENAME-release.apk" \
  "$DIST_DIR/$APK_BASENAME-release.apk.sha256" \
  "$DIST_DIR/$APK_BASENAME-$APP_VERSION-debug.apk" \
  "$DIST_DIR/$APK_BASENAME-$APP_VERSION-debug.apk.sha256" \
  "$DIST_DIR/$APK_BASENAME-$APP_VERSION-release.apk" \
  "$DIST_DIR/$APK_BASENAME-$APP_VERSION-release.apk.sha256" \
  "$DIST_DIR/$APK_BASENAME-release-unsigned.apk" \
  "$DIST_DIR/$APK_BASENAME-release-unsigned.apk.sha256"

DEBUG_APK="$PROJECT_DIR/app/build/outputs/apk/debug/app-debug.apk"
SIGNED_RELEASE_APK="$PROJECT_DIR/app/build/outputs/apk/release/app-release.apk"
RELEASE_LABEL="release"
RELEASE_APK="$SIGNED_RELEASE_APK"

if [[ ! -f "$SIGNED_RELEASE_APK" ]]; then
  echo "Signed release APK not found at $SIGNED_RELEASE_APK" >&2
  exit 1
fi

find_apksigner() {
  if command -v apksigner >/dev/null 2>&1; then
    command -v apksigner
    return
  fi

  local build_tools_dir="$ANDROID_SDK_ROOT/build-tools"
  if [[ -d "$build_tools_dir" ]]; then
    local candidate
    candidate="$(find "$build_tools_dir" -maxdepth 2 -type f -name apksigner | sort -r | head -n 1)"
    if [[ -n "$candidate" ]]; then
      echo "$candidate"
      return
    fi
  fi
}

if [[ "$RELEASE_MODE" == "production" ]]; then
  APKSIGNER_BIN="$(find_apksigner)"
  if [[ -z "${APKSIGNER_BIN:-}" ]]; then
    echo "Unable to locate apksigner for production signature verification." >&2
    exit 1
  fi

  SIGNING_REPORT_PATH="$DIST_DIR/$APK_BASENAME-release-signing.txt"
  "$APKSIGNER_BIN" verify --print-certs "$RELEASE_APK" > "$SIGNING_REPORT_PATH"

  if rg -qi "android debug|androiddebugkey|CN=Android Debug" "$SIGNING_REPORT_PATH"; then
    echo "Production Android release appears to be debug-signed." >&2
    exit 1
  fi
fi

cp "$DEBUG_APK" "$DIST_DIR/$APK_BASENAME-debug.apk"
cp "$RELEASE_APK" "$DIST_DIR/$APK_BASENAME-$RELEASE_LABEL.apk"
cp "$DEBUG_APK" "$DIST_DIR/$APK_BASENAME-$APP_VERSION-debug.apk"
cp "$RELEASE_APK" "$DIST_DIR/$APK_BASENAME-$APP_VERSION-$RELEASE_LABEL.apk"

shasum -a 256 "$DIST_DIR/$APK_BASENAME-debug.apk" > "$DIST_DIR/$APK_BASENAME-debug.apk.sha256"
shasum -a 256 "$DIST_DIR/$APK_BASENAME-$RELEASE_LABEL.apk" > "$DIST_DIR/$APK_BASENAME-$RELEASE_LABEL.apk.sha256"
shasum -a 256 "$DIST_DIR/$APK_BASENAME-$APP_VERSION-debug.apk" > "$DIST_DIR/$APK_BASENAME-$APP_VERSION-debug.apk.sha256"
shasum -a 256 "$DIST_DIR/$APK_BASENAME-$APP_VERSION-$RELEASE_LABEL.apk" > "$DIST_DIR/$APK_BASENAME-$APP_VERSION-$RELEASE_LABEL.apk.sha256"
