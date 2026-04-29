#!/bin/zsh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PACKAGE_PATH="$ROOT_DIR/native/macos/NotrusMac"
APP_PATH="$ROOT_DIR/dist/Notrus.app"
ZIP_PATH="$ROOT_DIR/dist/Notrus.zip"
APP_VERSION="${NOTRUS_MAC_VERSION:-0.3.4}"
RELEASE_LABEL="${NOTRUS_RELEASE_LABEL:-beta5}"
VERSIONED_ZIP_PATH="$ROOT_DIR/dist/Notrus-$APP_VERSION-$RELEASE_LABEL.zip"
CONFIGURATION="${NOTRUS_MAC_CONFIGURATION:-debug}"
PROTOCOL_HELPER_PATH="$ROOT_DIR/native/protocol-core/target/release/notrus-protocol-core"
CODESIGN_IDENTITY="${NOTRUS_CODESIGN_IDENTITY:--}"
ENTITLEMENTS_PATH="$ROOT_DIR/config/macos/NotrusMac.entitlements"
NOTARY_PROFILE="${NOTRUS_NOTARY_PROFILE:-}"
RELEASE_MODE="${NOTRUS_RELEASE_MODE:-local}"
BUILD_COUNTER_DIR="$ROOT_DIR/.build/build-counters"
BUILD_COUNTER_FILE="$BUILD_COUNTER_DIR/macos-$APP_VERSION-$RELEASE_LABEL.counter"
if [[ -n "${NOTRUS_BUILD_COUNTER:-}" ]]; then
  BUILD_COUNTER="$NOTRUS_BUILD_COUNTER"
else
  mkdir -p "$BUILD_COUNTER_DIR"
  PREVIOUS_BUILD_COUNTER="0"
  if [[ -f "$BUILD_COUNTER_FILE" ]]; then
    PREVIOUS_BUILD_COUNTER="$(cat "$BUILD_COUNTER_FILE")"
  fi
  BUILD_COUNTER="$((PREVIOUS_BUILD_COUNTER + 1))"
  printf "%s" "$BUILD_COUNTER" > "$BUILD_COUNTER_FILE"
fi
BUILD_NUMBER="${NOTRUS_BUILD_NUMBER:-$BUILD_COUNTER}"
BUILD_ID="${NOTRUS_BUILD_ID:-$APP_VERSION-$RELEASE_LABEL+mac.$BUILD_COUNTER.$(date -u +%Y%m%d%H%M%S)}"
ICONSET_DIR=""
LOCAL_VERIFICATION_PLIST_VALUE="<false/>"
FALLBACK_REPO_ICON_PATH="$ROOT_DIR/config/macos/AppIcon.icns"
FALLBACK_SYSTEM_ICON_PATH="/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/GenericApplicationIcon.icns"
RELEASE_APPROVALS_PATH="${NOTRUS_RELEASE_APPROVALS_PATH:-$ROOT_DIR/config/release/approvals.json}"

if [[ "$RELEASE_MODE" != "production" ]]; then
  LOCAL_VERIFICATION_PLIST_VALUE="<true/>"
fi

if [[ "$RELEASE_MODE" == "production" ]]; then
  NOTRUS_RELEASE_MODE="$RELEASE_MODE" \
  NOTRUS_RELEASE_APPROVALS_PATH="$RELEASE_APPROVALS_PATH" \
  node "$ROOT_DIR/scripts/verify-release-governance.mjs"
fi

zsh "$ROOT_DIR/scripts/build-mac-app.sh"
source "$ROOT_DIR/scripts/swift-env.sh"

BINARY_PATH="$(find "$PACKAGE_PATH/.build" -type f -path "*/$CONFIGURATION/NotrusMac" | head -n 1)"

if [[ -z "$BINARY_PATH" ]]; then
  echo "Unable to locate the built NotrusMac executable." >&2
  exit 1
fi

rm -rf \
  "$APP_PATH" \
  "$ZIP_PATH" \
  "$ROOT_DIR/dist/Notrus.app.sha256" \
  "$ROOT_DIR/dist/Notrus.zip.sha256" \
  "$VERSIONED_ZIP_PATH" \
  "$VERSIONED_ZIP_PATH.sha256"
mkdir -p "$APP_PATH/Contents/MacOS" "$APP_PATH/Contents/Resources" "$APP_PATH/Contents/Helpers"

ICONSET_DIR="$(mktemp -d "$ROOT_DIR/.build/tmp/notrus-iconset.XXXXXX.iconset")"
trap '[[ -n "$ICONSET_DIR" ]] && rm -rf "$ICONSET_DIR"' EXIT

cp "$BINARY_PATH" "$APP_PATH/Contents/MacOS/Notrus"
chmod +x "$APP_PATH/Contents/MacOS/Notrus"

if [[ -x "$PROTOCOL_HELPER_PATH" ]]; then
  cp "$PROTOCOL_HELPER_PATH" "$APP_PATH/Contents/Helpers/notrus-protocol-core"
  cp "$PROTOCOL_HELPER_PATH" "$APP_PATH/Contents/MacOS/notrus-protocol-core"
  cp "$PROTOCOL_HELPER_PATH" "$APP_PATH/Contents/Resources/notrus-protocol-core"
  chmod +x "$APP_PATH/Contents/Helpers/notrus-protocol-core"
  chmod +x "$APP_PATH/Contents/MacOS/notrus-protocol-core"
  chmod +x "$APP_PATH/Contents/Resources/notrus-protocol-core"
else
  echo "Unable to locate the built notrus-protocol-core helper." >&2
  exit 1
fi

swift "$ROOT_DIR/scripts/render-mac-icon.swift" "$ICONSET_DIR"
if ! iconutil -c icns "$ICONSET_DIR" -o "$APP_PATH/Contents/Resources/AppIcon.icns"; then
  if [[ -f "$FALLBACK_REPO_ICON_PATH" ]]; then
    cp "$FALLBACK_REPO_ICON_PATH" "$APP_PATH/Contents/Resources/AppIcon.icns"
    echo "iconutil rejected the generated iconset; used fallback repo icon at $FALLBACK_REPO_ICON_PATH"
  elif [[ -f "$FALLBACK_SYSTEM_ICON_PATH" ]]; then
    cp "$FALLBACK_SYSTEM_ICON_PATH" "$APP_PATH/Contents/Resources/AppIcon.icns"
    echo "iconutil rejected the generated iconset; used fallback system icon at $FALLBACK_SYSTEM_ICON_PATH"
  else
    echo "iconutil failed and no fallback AppIcon.icns was available." >&2
    exit 1
  fi
fi

cat > "$APP_PATH/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleExecutable</key>
  <string>Notrus</string>
  <key>CFBundleDisplayName</key>
  <string>Notrus</string>
  <key>CFBundleIconFile</key>
  <string>AppIcon</string>
  <key>CFBundleIconName</key>
  <string>AppIcon</string>
  <key>CFBundleIdentifier</key>
  <string>com.notrus.mac</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>Notrus</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>$APP_VERSION</string>
  <key>CFBundleVersion</key>
  <string>$BUILD_NUMBER</string>
  <key>NotrusBuildCounter</key>
  <string>$BUILD_COUNTER</string>
  <key>NotrusBuildID</key>
  <string>$BUILD_ID</string>
  <key>NotrusLocalVerificationBuild</key>
  $LOCAL_VERIFICATION_PLIST_VALUE
  <key>LSMinimumSystemVersion</key>
  <string>13.0</string>
  <key>NSApplicationIconFile</key>
  <string>AppIcon</string>
  <key>NSAppTransportSecurity</key>
  <dict>
    <key>NSAllowsArbitraryLoads</key>
    <false/>
    <key>NSAllowsLocalNetworking</key>
    <true/>
    <key>NSExceptionDomains</key>
    <dict>
      <key>127.0.0.1</key>
      <dict>
        <key>NSExceptionAllowsInsecureHTTPLoads</key>
        <true/>
      </dict>
      <key>localhost</key>
      <dict>
        <key>NSExceptionAllowsInsecureHTTPLoads</key>
        <true/>
      </dict>
    </dict>
  </dict>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSSupportsAutomaticGraphicsSwitching</key>
  <true/>
</dict>
</plist>
PLIST

if command -v codesign >/dev/null 2>&1; then
  if [[ "$RELEASE_MODE" == "production" && "$CODESIGN_IDENTITY" == "-" ]]; then
    echo "Production macOS releases require a non-ad-hoc NOTRUS_CODESIGN_IDENTITY." >&2
    exit 1
  fi

  if [[ "$RELEASE_MODE" == "production" && -z "$NOTARY_PROFILE" ]]; then
    echo "Production macOS releases require NOTRUS_NOTARY_PROFILE for notarization." >&2
    exit 1
  fi

  codesign --force --options runtime --sign "$CODESIGN_IDENTITY" "$APP_PATH/Contents/Helpers/notrus-protocol-core" >/dev/null
  codesign --force --options runtime --sign "$CODESIGN_IDENTITY" "$APP_PATH/Contents/MacOS/notrus-protocol-core" >/dev/null
  codesign --force --options runtime --sign "$CODESIGN_IDENTITY" "$APP_PATH/Contents/Resources/notrus-protocol-core" >/dev/null
  if [[ "$RELEASE_MODE" == "production" && "$CODESIGN_IDENTITY" != "-" ]]; then
    codesign --force --options runtime --entitlements "$ENTITLEMENTS_PATH" --sign "$CODESIGN_IDENTITY" "$APP_PATH" >/dev/null
  else
    codesign --force --options runtime --sign "$CODESIGN_IDENTITY" "$APP_PATH" >/dev/null
  fi
  codesign --verify --deep --strict "$APP_PATH" >/dev/null
fi

for helper in \
  "$APP_PATH/Contents/Helpers/notrus-protocol-core" \
  "$APP_PATH/Contents/MacOS/notrus-protocol-core" \
  "$APP_PATH/Contents/Resources/notrus-protocol-core"
do
  if ! printf '{"command":"profile-snapshot"}' | "$helper" >/dev/null 2>&1; then
    echo "The packaged notrus-protocol-core helper failed its smoke test at $helper." >&2
    exit 1
  fi
done

if [[ ! -x "$APP_PATH/Contents/Helpers/notrus-protocol-core" || ! -x "$APP_PATH/Contents/MacOS/notrus-protocol-core" || ! -x "$APP_PATH/Contents/Resources/notrus-protocol-core" ]]; then
  echo "The packaged notrus-protocol-core helper was not embedded in every required bundle location." >&2
  exit 1
fi

if command -v ditto >/dev/null 2>&1; then
  ditto -c -k --keepParent "$APP_PATH" "$ZIP_PATH"
  cp "$ZIP_PATH" "$VERSIONED_ZIP_PATH"
fi

if [[ -n "$NOTARY_PROFILE" && "$CODESIGN_IDENTITY" != "-" ]]; then
  xcrun notarytool submit "$ZIP_PATH" --keychain-profile "$NOTARY_PROFILE" --wait
  xcrun stapler staple "$APP_PATH"
fi

if command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$APP_PATH/Contents/MacOS/Notrus" > "$ROOT_DIR/dist/Notrus.app.sha256"
  if [[ -f "$ZIP_PATH" ]]; then
    shasum -a 256 "$ZIP_PATH" > "$ROOT_DIR/dist/Notrus.zip.sha256"
  fi
  if [[ -f "$VERSIONED_ZIP_PATH" ]]; then
    shasum -a 256 "$VERSIONED_ZIP_PATH" > "$VERSIONED_ZIP_PATH.sha256"
  fi
fi

echo "Packaged $APP_PATH"
