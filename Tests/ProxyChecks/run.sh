#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT="${SEARCH_CHECK_OUTPUT:?Set SEARCH_CHECK_OUTPUT to a scratch directory}"
mkdir -p "$OUT/ProxyChecks.app/Contents/MacOS"
cat > "$OUT/ProxyChecks.app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.nathandiorr.search.proxychecks</string><key>CFBundleExecutable</key><string>ProxyChecks</string><key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/></dict></dict></plist>
PLIST
swiftc -parse-as-library -swift-version 5 -target arm64-apple-macos14.0 Sources/Search/Proxy.swift Sources/Search/NordProxy.swift Tests/ProxyChecks/main.swift -o "$OUT/ProxyChecks.app/Contents/MacOS/ProxyChecks"
codesign --force --sign - "$OUT/ProxyChecks.app"
"$OUT/ProxyChecks.app/Contents/MacOS/ProxyChecks" "$@"
