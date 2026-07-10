#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${COMPANY_VPN_CLIENT_VERSION:-client-dev}"
WEB_URL="${COMPANY_VPN_WEB_URL:-http://172.16.188.135:8080}"
CLIENT_KEY="${COMPANY_VPN_CLIENT_KEY:-company-vpn-global-client-key-v1-20260621}"
DIST_DIR="${COMPANY_VPN_DIST_DIR:-$ROOT_DIR/client/dist}"
PACKAGE_DIR="${COMPANY_VPN_PACKAGE_DIR:-$ROOT_DIR/client/package}"

mkdir -p "$DIST_DIR" "$PACKAGE_DIR"

log() {
  printf '[platform] %s\n' "$*"
}

swift_escape() {
  python3 - "$1" <<'PY'
import json
import sys
print(json.dumps(sys.argv[1], ensure_ascii=False))
PY
}

write_apple_config() {
  local config_file="$ROOT_DIR/client-apple/Sources/CompanyVPNShared/GeneratedConfig.swift"
  cat > "$config_file" <<EOF
import Foundation

public enum GeneratedCompanyVPNConfig {
    public static let webURL = $(swift_escape "$WEB_URL")
    public static let cryptoKey = $(swift_escape "$CLIENT_KEY")
    public static let version = $(swift_escape "$VERSION")
}
EOF
}

zip_dir() {
  local source_dir="$1"
  local zip_path="$2"
  rm -f "$zip_path"
  (cd "$source_dir" && zip -qr "$zip_path" .)
}

build_macos() {
  if [[ ! -d "$ROOT_DIR/client-apple" ]]; then
    log "macOS 客户端源码不存在，跳过。"
    return 0
  fi
  if ! command -v swift >/dev/null 2>&1; then
    log "未安装 Swift 工具链，跳过 macOS 客户端。"
    return 0
  fi
  case "$(uname -s)" in
    Darwin) ;;
    *)
      log "当前不是 macOS，跳过 macOS 客户端编译。"
      return 0
      ;;
  esac
  write_apple_config
  log "开始编译 macOS 客户端..."
  (cd "$ROOT_DIR/client-apple" && swift build -c release)
  local out_dir="$PACKAGE_DIR/macos"
  local app_dir="$out_dir/CompanyVPN.app"
  rm -rf "$out_dir"
  mkdir -p "$app_dir/Contents/MacOS" "$app_dir/Contents/Resources"
  cp "$ROOT_DIR/client-apple/.build/release/CompanyVPNMac" "$app_dir/Contents/MacOS/CompanyVPN"
  chmod +x "$app_dir/Contents/MacOS/CompanyVPN"
  cat > "$app_dir/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>CompanyVPN</string>
  <key>CFBundleIdentifier</key>
  <string>com.companyvpn.client</string>
  <key>CFBundleName</key>
  <string>Company VPN</string>
  <key>CFBundleDisplayName</key>
  <string>Company VPN</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>$VERSION</string>
  <key>CFBundleVersion</key>
  <string>$VERSION</string>
  <key>LSMinimumSystemVersion</key>
  <string>13.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
EOF
  if command -v codesign >/dev/null 2>&1; then
    codesign --force --deep --sign - "$app_dir" >/dev/null 2>&1 || true
  fi
  zip_dir "$out_dir" "$DIST_DIR/client-macos-$VERSION.zip"
  log "macOS 客户端打包完成: client-macos-$VERSION.zip"
}

build_ios() {
  if [[ ! -d "$ROOT_DIR/client-ios" ]]; then
    log "iOS 客户端源码不存在，跳过。"
    return 0
  fi
  local out_dir="$PACKAGE_DIR/ios-source"
  rm -rf "$out_dir"
  mkdir -p "$out_dir"
  cp -R "$ROOT_DIR/client-ios/"* "$out_dir/"
  zip_dir "$out_dir" "$DIST_DIR/client-ios-source-$VERSION.zip"
  log "iOS 需要 Apple Developer Team 和 Network Extension 签名；已生成源码包: client-ios-source-$VERSION.zip"
}

build_android() {
  if [[ ! -d "$ROOT_DIR/client-android" ]]; then
    log "Android 客户端源码不存在，跳过。"
    return 0
  fi
  if ! command -v gradle >/dev/null 2>&1; then
    log "未安装 Gradle，跳过 Android APK 编译。"
    return 0
  fi
  if [[ -z "${ANDROID_HOME:-}" && -z "${ANDROID_SDK_ROOT:-}" ]]; then
    log "未配置 ANDROID_HOME/ANDROID_SDK_ROOT，跳过 Android APK 编译。"
    return 0
  fi
  log "开始编译 Android 客户端..."
  (cd "$ROOT_DIR/client-android" && COMPANY_VPN_CLIENT_VERSION="$VERSION" gradle --no-daemon :app:assembleRelease)
  local apk="$ROOT_DIR/client-android/app/build/outputs/apk/release/app-release.apk"
  if [[ -f "$apk" ]]; then
    cp "$apk" "$DIST_DIR/client-android-$VERSION.apk"
    log "Android 客户端打包完成: client-android-$VERSION.apk"
  else
    log "Android 构建结束但没有找到 APK。"
  fi
}

build_macos
build_ios
build_android

find "$DIST_DIR" -maxdepth 1 -type f \( -name 'client-macos-*.zip' -o -name 'client-ios-source-*.zip' -o -name 'client-android-*.apk' \) \
  ! -name "*$VERSION*" -delete

log "平台客户端构建流程结束。"
