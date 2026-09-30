# Search VPN build

## Problem and usage

NordVPN 6.1.1 uses chrome.proxy.settings PAC rules and asynchronous webRequest proxy authentication. Upstream Search saves these settings without routing WebKit traffic, so its Secured badge can show the normal IP. This fork makes Connect, Disconnect, country changes and host-based bypass rules control browser page traffic.

Build with `SEARCH_APP_NAME='Search VPN' SEARCH_BUNDLE_ID=com.nathandiorr.search.vpn SEARCH_SIGN_IDENTITY='' ./build.sh`. Open the separate app, install the official Nord extension in Settings > Extensions and sign in. Its controls apply to normal and private WebKit stores. The app, profile, defaults and proxy Keychain service are separate from the original Search installation.

```swift
try await NordProxy.shared.set(value, context: context)
BrowserProxy.shared.attach(configuration.websiteDataStore)
NordProxy.shared.stop()
```

## Ownership and shape

BrowserProxy remains the single owner of weak data-store registration and manual settings from upstream #510. NordProxy owns the authorized extension's setting transitions and in-memory authentication continuations. NordRelay accepts bounded authenticated CONNECT tunnels on loopback; CFNetwork evaluates Nord's host-based PAC for each destination. Network.framework establishes the chosen upstream CONNECT route, including TLS certificate validation and proxy credentials. Browser TLS passes through unchanged.

Settings operations have their own generation so late country changes cannot override Disconnect. Authentication has a separate generation so worker reconnection cancels pending credentials without invalidating settings. A remembered connected profile starts with a dead, fail-closed route before any tabs load. New relay configuration replaces it only after readiness. The relay keeps one stable WebKit endpoint while Nord is enabled. Country changes and Disconnect close its existing tunnels and change its PAC to the new route or DIRECT; they preserve the calling background worker. Entering or leaving extension control closes this app's WebKit network process to prevent reuse of earlier direct connections. Initial preparation occurs before controller.load. Manual proxy settings require disabling the Nord extension first.

## Alternatives and tradeoffs

Manual HTTPS proxy settings alone cannot satisfy the requested extension buttons. Translating PAC once into a global proxy loses per-host bypass and preflight routes. The loopback relay preserves those rules and leaves CONNECT, TLS and authentication transport to Network.framework rather than implementing them again. Multiple PAC alternatives are refused because implicit direct fallback would contradict protection. Nord's localhost:0 kill-switch result is explicitly blocked.

This adapter is intentionally bound to Nord 6.1.1. General extension compatibility, path-specific arbitrary PAC, other extension versions and a system-wide VPN are outside its contract. WebKit's native local-address proxy exemptions still apply. Native auxiliary URLSession services, WebRTC and other application traffic are outside the browsing proxy. Nord's own PAC may deliberately bypass its account/services and user-selected sites.

The native credential channel is available only to the authorized Nord context with proxy and webRequest permissions. Per-request unpredictable tokens bind replies to pending requests; no website runtime channel carries credentials. The loopback listener uses a random per-listener credential, caps connections and headers, bounds establishment and stops obsolete tunnels. Credentials are never written by this adapter.

## Verification and remaining live acceptance

Standalone checks compile the production proxy, PAC, relay and JavaScript authentication bridge, exercising actual normal/private WebKit traffic against an authenticated local CONNECT fixture. The installed Command Line Tools lack XCTest, so swift test cannot run here. Live acceptance still requires Nord sign-in, changed public IP in two independent checks, country change, Disconnect, private tabs, restart and other browsers remaining direct. Ad-hoc signing supports this Mac; distributable signing/notarization is separate.
