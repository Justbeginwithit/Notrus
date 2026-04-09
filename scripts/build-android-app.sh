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
./gradlew assembleDebug
