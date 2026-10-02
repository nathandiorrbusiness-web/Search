import AppKit
import Foundation
import Network
import WebKit

// The proxy owner is compiled from the product source. Only its storage
// environment is replaced, so these checks never read a browser's profile.
enum Store {
    static let settings = UserDefaults(suiteName: "Search.ProxyChecks.\(UUID())")!
    static let world: String? = "proxy-checks"
}

@available(macOS 15.4, *)
@MainActor
enum Extensions {
    static var rememberedNordIsEnabled = false
    static var remembered: [String: Any] = [:]
    static func settings(for id: String) -> [String: Any] { remembered }
}
@available(macOS 15.4, *)
@MainActor
enum ExtensionShims {
    static func allowed(_ id: String, context: WKWebExtensionContext) -> Set<String> { ["proxy", "webRequest"] }
}

@MainActor
final class Navigation: NSObject, WKNavigationDelegate {
    private var turn: UUID?
    private var completion: ((Result<Void, Error>) -> Void)?
    func load(_ url: URL, in web: WKWebView) async throws {
        try await withCheckedThrowingContinuation { continuation in
            let token = UUID(); turn = token
            completion = { continuation.resume(with: $0) }
            web.navigationDelegate = self
            web.load(URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData))
            DispatchQueue.main.asyncAfter(deadline: .now() + 15) { [weak self] in
                guard self?.turn == token else { return }
                self?.finish(.failure(NSError(domain: "ProxyChecks.Timeout", code: 1)))
            }
        }
    }
    private func finish(_ result: Result<Void, Error>) {
        let done = completion
        completion = nil
        turn = nil
        done?(result)
    }
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) { finish(.success(())) }
    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) { finish(.failure(error)) }
    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) { finish(.failure(error)) }
}

// Runs the product shim in a real service worker. In particular, WebKit owns
// onAuthRequired and its native-message dispatch, which a JSContext cannot model.
@available(macOS 15.4, *)
@MainActor
final class WorkerBridge: NSObject, WKWebExtensionControllerDelegate {
    func webExtensionController(_ controller: WKWebExtensionController, sendMessage message: Any,
                                toApplicationWithIdentifier name: String?, for context: WKWebExtensionContext) async throws -> Any? {
        guard name == "search", let request = message as? [String: Any],
              let api = request["api"] as? String, let args = request["args"] as? [Any] else { return nil }
        do {
            if api == "nord.receive", args.isEmpty { return ["value": try await NordProxy.shared.receive(context)] }
            if api == "nord.answer", args.count == 2, let token = args[0] as? String,
               let result = args[1] as? [String: Any] {
                try NordProxy.shared.answer(token, result: result, context: context)
                return [:]
            }
            return ["error": "Unexpected fixture API"]
        } catch { return ["error": error.localizedDescription] }
    }
}

@main
struct ProxyChecks {
    @MainActor static func main() {
        _ = NSApplication.shared
        Task { @MainActor in
            do { guard #available(macOS 15.4, *) else { throw NSError(domain: "requires macOS 15.4", code: 1) }; try await run(); print("PASS: real WebKit worker authentication (normal/private) and unauthorized/stopped channel rejection, PAC HTTPS/plaintext distinction and kill switch, startup blocking, disconnect race, TCP half-close, authenticated relay/direct bypass, normal/private WebKit routing, validation, persistence, failure atomicity, unreachable-proxy failure and reset"); exit(0) }
            catch { print("FAIL: \(error)"); exit(1) }
        }
        NSApp.run()
    }

    static func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        if !condition() { throw NSError(domain: message, code: 1) }
    }

    @available(macOS 15.4, *)
    @MainActor static func checkHalfClose(script: String) async throws {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        let listener = try NWListener(using: parameters)
        var tunnels: [NordRelay.Tunnel] = []
        var completions: [String?] = []
        defer { listener.cancel(); tunnels.forEach { $0.end() } }
        listener.newConnectionHandler = { connection in
            MainActor.assumeIsolated {
                let tunnel = NordRelay.Tunnel(client: connection, script: script, localSecret: "fixture-token") { _, _, _ in ["username": "fixture", "password": "fixture-password", "requestID": "half-close-fixture"] }
                tunnel.onCompletion = { _, _, error in completions.append(error) }
                tunnels.append(tunnel); tunnel.start()
            }
        }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            var done = false
            listener.stateUpdateHandler = { state in MainActor.assumeIsolated {
                guard !done else { return }
                switch state {
                case .ready: done = true; continuation.resume()
                case .failed(let error): done = true; continuation.resume(throwing: error)
                default: break
                }
            } }
            listener.start(queue: .main)
        }
        guard let port = listener.port else { throw NSError(domain: "half-close listener timed out", code: 1) }
        let client = NWConnection(host: "127.0.0.1", port: port, using: .tcp)
        defer { client.cancel() }
        let basic = Data("Search:fixture-token".utf8).base64EncodedString()
        let connect = "CONNECT half-close.invalid:80 HTTP/1.1\r\nProxy-Authorization: Basic \(basic)\r\n\r\n"
        let request = "GET / HTTP/1.1\r\nHost: half-close.invalid\r\nConnection: close\r\n\r\n"
        let received: Data = try await withCheckedThrowingContinuation { continuation in
            var result = Data(), done = false, sentRequest = false
            func finish(_ error: Error? = nil) {
                guard !done else { return }; done = true
                if let error { continuation.resume(throwing: error) } else { continuation.resume(returning: result) }
            }
            func read() {
                client.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, complete, error in
                    MainActor.assumeIsolated {
                        if let data { result.append(data) }
                        if !sentRequest, String(decoding: result, as: UTF8.self).contains("200 Connection Established\r\n\r\n") {
                            guard completions.isEmpty else { finish(NSError(domain: "CONNECT readiness falsely completed the request", code: 1)); return }
                            sentRequest = true
                            client.send(content: Data(request.utf8), contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { error in
                                MainActor.assumeIsolated { if let error { finish(error) } }
                            })
                        }
                        if error != nil || complete { finish(error) } else { read() }
                    }
                }
            }
            client.stateUpdateHandler = { state in MainActor.assumeIsolated {
                switch state {
                case .ready:
                    client.send(content: Data(connect.utf8), completion: .contentProcessed { error in MainActor.assumeIsolated { if let error { finish(error) } } }); read()
                case .failed(let error): finish(error)
                default: break
                }
            } }
            client.start(queue: .main)
            Task { try? await Task.sleep(for: .seconds(10)); finish(NSError(domain: "half-close timeout: client=\(client.state) tunnels=\(tunnels.count) header=\(tunnels.first?.header.count ?? 0) ready=\(tunnels.first?.ready ?? false) ended=\(tunnels.first?.ended ?? false) upstream=\(String(describing: tunnels.first?.upstream?.state))", code: 1)) }
        }
        try require(String(decoding: received, as: UTF8.self).contains("authenticated WebKit traffic"), "client half-close dropped the upstream response")
        for _ in 0..<10 where completions.isEmpty { try await Task.sleep(for: .milliseconds(10)) }
        try require(completions.count == 1, "tunnel termination did not release pending authentication exactly once: \(completions)")
    }

    @available(macOS 15.4, *)
    @MainActor static func checkWorker(script: String) async throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("nord-worker-check-\(UUID())")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let manifest: [String: Any] = ["manifest_version": 3, "name": "Nord worker fixture", "description": "Isolated proxy test",
            "version": "6.1.1", "permissions": ["proxy", "nativeMessaging", "webRequest"],
            "host_permissions": ["<all_urls>"], "background": ["service_worker": "worker.js"]]
        try JSONSerialization.data(withJSONObject: manifest).write(to: folder.appendingPathComponent("manifest.json"))
        let worker = #"""
        const background = true, runtime = chrome.runtime, kept = new Set();
        const put = (o, k, v) => { kept.add(o); try { Object.defineProperty(o, k, {value:v, configurable:true, writable:true, enumerable:true}); } catch(e) { try { o[k] = v; } catch(e2) {} } };
        function event() { const listeners = new Set(); return {listeners, addListener(f) {listeners.add(f);}, removeListener(f) {listeners.delete(f);}}; }
        const native = (api, args) => runtime.sendNativeMessage("search", {api, args}).then(reply => {if (reply.error) throw new Error(reply.error); return reply.value;});
        put(chrome, "proxy", {settings:{onChange:event()}, onProxyError:event()});
        """# + NordProxy.shim + #"""
        let calls = 0;
        chrome.webRequest.onAuthRequired.addListener((details, done) => {
          if (!details.isProxy || !details.challenger || !details.requestId) return done({cancel:true});
          setTimeout(() => done({authCredentials:{username:"fixture", password:"fixture-password"}}), 25);
          calls++;
        }, {urls:["<all_urls>"]}, ["asyncBlocking", "responseHeaders"]);
        """#
        try worker.write(to: folder.appendingPathComponent("worker.js"), atomically: true, encoding: .utf8)
        let configuration = WKWebExtensionController.Configuration.nonPersistent()
        configuration.defaultWebsiteDataStore = .nonPersistent()
        let viewConfiguration = WKWebViewConfiguration(); viewConfiguration.websiteDataStore = configuration.defaultWebsiteDataStore!
        configuration.webViewConfiguration = viewConfiguration
        let controller = WKWebExtensionController(configuration: configuration), bridge = WorkerBridge()
        controller.delegate = bridge
        let ext = try await WKWebExtension(resourceBaseURL: folder), context = WKWebExtensionContext(for: ext)
        context.uniqueIdentifier = NordProxy.extensionID
        context.setPermissionStatus(.grantedExplicitly, for: .nativeMessaging)
        context.setPermissionStatus(.grantedExplicitly, for: .webRequest)
        BrowserProxy.shared.attach(viewConfiguration.websiteDataStore)
        await NordProxy.shared.restore(context)
        try controller.load(context)
        defer { NordProxy.shared.stop(); try? controller.unload(context) }
        try await context.loadBackgroundContent()
        try await NordProxy.shared.set(["mode": "pac_script", "pacScript": ["data": script]], context: context)
        for store in [viewConfiguration.websiteDataStore, WKWebsiteDataStore.nonPersistent()] {
            let views = WKWebViewConfiguration(); views.websiteDataStore = store; BrowserProxy.shared.attach(store)
            let web = WKWebView(frame: .zero, configuration: views), navigation = Navigation()
            try await navigation.load(URL(string: "http://route-test.invalid/worker-\(UUID())")!, in: web)
            let body = try await web.evaluateJavaScript("document.body.innerText") as? String ?? ""
            try require(body.contains("authenticated WebKit traffic"), "real worker did not supply proxy credentials")
        }
        for _ in 0..<600 { NordProxy.shared.completed(UUID().uuidString, url: "http://route-test.invalid/fixture") }
        let checks = NordProxy.shared.diagnostics["checkpoints"] as? [String] ?? []
        try require(checks.contains("receiver-overflow-blocked"), "stalled receiver did not block routing")
        let blockedView = WKWebView(frame: .zero, configuration: viewConfiguration), blockedNavigation = Navigation()
        var blocked = false
        do { try await blockedNavigation.load(URL(string: "http://route-test.invalid/overflow")!, in: blockedView) }
        catch { blocked = true }
        try require(blocked, "receiver overflow left routing active")
        try await NordProxy.shared.set(["mode": "pac_script", "pacScript": ["data": script]], context: context)
        try await blockedNavigation.load(URL(string: "http://route-test.invalid/recovered")!, in: blockedView)
        let recovered = try await blockedView.evaluateJavaScript("document.body.innerText") as? String ?? ""
        try require(recovered.contains("authenticated WebKit traffic"), "worker did not recover after an explicit new setting")
        let impostor = WKWebExtensionContext(for: ext); impostor.uniqueIdentifier = "fixture-impostor"
        do { _ = try await NordProxy.shared.receive(impostor); throw NSError(domain: "another extension read Nord events", code: 1) }
        catch { try require((error as NSError).domain == "Search.NordProxy", "wrong unauthorized-context rejection") }
        do { try NordProxy.shared.answer(UUID().uuidString, result: [:], context: impostor); throw NSError(domain: "another extension answered Nord auth", code: 1) }
        catch { try require((error as NSError).domain == "Search.NordProxy", "wrong unauthorized-answer rejection") }
        // A stopped channel rejects new polls and releases pending credentials.
        NordProxy.shared.stop()
        try require(NordProxy.shared.diagnostics["pendingAuthentication"] as? Int == 0, "stop left pending authentication")
        do { _ = try await NordProxy.shared.receive(context); throw NSError(domain: "stopped context retained channel", code: 1) }
        catch { try require((error as NSError).domain == "Search.NordProxy", "wrong stopped-channel rejection") }
    }

    @available(macOS 15.4, *)
    @MainActor static func run() async throws {
        guard CommandLine.arguments.count >= 2, let port = UInt16(CommandLine.arguments[1]) else { fatalError("pass fixture port") }
        let script = "function FindProxyForURL(url, host) { return dnsDomainIs(host, '.invalid') ? 'PROXY 127.0.0.1:\(port)' : 'DIRECT'; }"
        let proxiedRoute = try NordRoute.evaluate(script, host: "route-test.invalid", port: 80)
        let directRoute = try NordRoute.evaluate(script, host: "example.com", port: 443)
        try require(proxiedRoute.kind == .http, "PAC lost proxy route")
        try require(directRoute.kind == .direct, "PAC lost direct bypass")
        var rejectedPAC = false
        do { _ = try NordRoute.evaluate("function FindProxyForURL() { return 'PROXY 127.0.0.1:1; DIRECT'; }", host: "test.invalid", port: 443) }
        catch { rejectedPAC = true }
        try require(rejectedPAC, "PAC fallback was silently accepted")
        let secure = try NordRoute.evaluate("function FindProxyForURL() { return 'HTTPS proxy.example:443'; }", host: "test.invalid", port: 443)
        let plain = try NordRoute.evaluate("function FindProxyForURL() { return 'PROXY proxy.example:80'; }", host: "test.invalid", port: 443)
        try require(secure.kind == .https && plain.kind == .http, "PAC confused proxy TLS with destination TLS")
        let commented = try NordRoute.evaluate("function FindProxyForURL() { return 'HTTPS proxy.example:443'; }// EOF comment", host: "test.invalid", port: 443)
        try require(commented.kind == .https, "PAC EOF comment swallowed TLS adapter")
        let killed = try NordRoute.evaluate("function FindProxyForURL() { return 'PROXY localhost:0'; }", host: "test.invalid", port: 443)
        try require(killed.kind == .blocked, "Nord kill switch was not blocked")
        Extensions.rememberedNordIsEnabled = true
        Extensions.remembered = ["proxy.settings": ["mode": "pac_script", "pacScript": ["data": script]]]
        let startup = BrowserProxy(defaults: Store.settings, password: "", savePassword: { _ in })
        let startupStore = WKWebsiteDataStore.nonPersistent(); startup.attach(startupStore)
        try require(startupStore.proxyConfigurations.count == 1 && !startupStore.proxyConfigurations[0].allowFailover, "startup leaked a remembered connected profile")
        Extensions.rememberedNordIsEnabled = false; Extensions.remembered = [:]
        let temporary = FileManager.default.temporaryDirectory.appendingPathComponent("proxy-extension-\(UUID())")
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: temporary) }
        let manifest: [String: Any] = ["manifest_version": 3, "name": "Proxy fixture", "version": "6.1.1", "permissions": ["proxy", "webRequest"]]
        try JSONSerialization.data(withJSONObject: manifest).write(to: temporary.appendingPathComponent("manifest.json"))
        let ext = try await WKWebExtension(resourceBaseURL: temporary)
        let context = WKWebExtensionContext(for: ext); context.uniqueIdentifier = NordProxy.extensionID
        let sharedStore = WKWebsiteDataStore.nonPersistent(); BrowserProxy.shared.attach(sharedStore)
        let change = Task { try await NordProxy.shared.set(["mode": "pac_script", "pacScript": ["data": script]], context: context) }
        await Task.yield()
        NordProxy.shared.stop()
        do { try await change.value; throw NSError(domain: "stale change succeeded after disconnect", code: 1) }
        catch is CancellationError {}
        try require(sharedStore.proxyConfigurations.isEmpty, "stale change reinstated proxy after disconnect")
        try await checkHalfClose(script: script)
        try await checkWorker(script: script)
        let defaults = Store.settings
        let proxy = BrowserProxy(defaults: defaults, password: "", savePassword: { _ in })
        let value = ProxySettingsValue(mode: .http, host: "127.0.0.1", port: String(port), username: "fixture")
        try require(value.validation == nil, "valid configuration")
        for bad in ["", "0", "65536", "abc"] {
            var invalid = value; invalid.port = bad
            try require(invalid.validation != nil, "invalid port accepted")
        }
        let ordinary = WKWebsiteDataStore(forIdentifier: UUID())
        let privateStore = WKWebsiteDataStore.nonPersistent()
        proxy.attach(ordinary); proxy.attach(privateStore)
        try proxy.save(value, password: "fixture-password")
        for store in [ordinary, privateStore] {
            try require(store.proxyConfigurations.count == 1 && !store.proxyConfigurations[0].allowFailover, "proxy store configuration")
            let config = WKWebViewConfiguration(); config.websiteDataStore = store
            let web = WKWebView(frame: .zero, configuration: config)
            let navigation = Navigation()
            try await navigation.load(URL(string: "http://route-test.invalid/\(UUID())")!, in: web)
            let body = try await web.evaluateJavaScript("document.body.innerText") as? String ?? ""
            try require(body.contains("authenticated WebKit traffic"), "traffic did not reach authenticated proxy")
        }
        let relay = try await NordRelay.start(script: script) { _, _, _ in ["username": "fixture", "password": "fixture-password"] }
        defer { relay.stop() }
        proxy.extensionOverride(relay.configuration)
        let relayedConfig = WKWebViewConfiguration(); relayedConfig.websiteDataStore = WKWebsiteDataStore.nonPersistent()
        proxy.attach(relayedConfig.websiteDataStore)
        let relayed = WKWebView(frame: .zero, configuration: relayedConfig)
        let relayedNavigation = Navigation()
        try await relayedNavigation.load(URL(string: "http://route-test.invalid/relay-\(UUID())")!, in: relayed)
        let relayBody = try await relayed.evaluateJavaScript("document.body.innerText") as? String ?? ""
        try require(relayBody.contains("authenticated WebKit traffic"), "PAC relay did not authenticate upstream")
        try await relayedNavigation.load(URL(string: "https://example.com/?bypass=\(UUID())")!, in: relayed)
        let bypassBody = try await relayed.evaluateJavaScript("document.body.innerText") as? String ?? ""
        try require(bypassBody.contains("documentation examples"), "PAC direct bypass did not work: \(bypassBody.prefix(200))")
        relay.update(script: "function FindProxyForURL() { return 'DIRECT'; }")
        try await relayedNavigation.load(URL(string: "http://example.com/?disconnect=\(UUID())")!, in: relayed)
        let disconnected = try await relayed.evaluateJavaScript("document.body.innerText") as? String ?? ""
        try require(disconnected.contains("documentation examples"), "stable relay disconnect did not go direct")
        relay.update(script: "function FindProxyForURL() { return 'PROXY localhost:0'; }")
        var blockedExisting = false
        do { try await relayedNavigation.load(URL(string: "http://example.com/?kill=\(UUID())")!, in: relayed) }
        catch { blockedExisting = true }
        try require(blockedExisting, "relay update reused a previous direct connection")
        relay.update(script: script)
        try await relayedNavigation.load(URL(string: "http://route-test.invalid/reconnect-\(UUID())")!, in: relayed)
        let reconnected = try await relayed.evaluateJavaScript("document.body.innerText") as? String ?? ""
        try require(reconnected.contains("authenticated WebKit traffic"), "stable relay reconnect missed the route")
        proxy.extensionOverride(nil)
        if CommandLine.arguments.count > 2, let tlsPort = UInt16(CommandLine.arguments[2]) {
            let secureScript = "function FindProxyForURL() { return 'HTTPS 127.0.0.1:\(tlsPort)'; }"
            let secureRelay = try await NordRelay.start(script: secureScript) { _, _, _ in ["username": "fixture", "password": "fixture-password"] }
            proxy.extensionOverride(secureRelay.configuration)
            let tlsConfiguration = WKWebViewConfiguration(); tlsConfiguration.websiteDataStore = WKWebsiteDataStore.nonPersistent()
            proxy.attach(tlsConfiguration.websiteDataStore)
            let tlsWeb = WKWebView(frame: .zero, configuration: tlsConfiguration)
            let tlsNavigation = Navigation()
            var rejectedTLS = false
            do { try await tlsNavigation.load(URL(string: "http://untrusted-proxy.invalid/")!, in: tlsWeb) }
            catch { rejectedTLS = true }
            try require(rejectedTLS, "untrusted proxy certificate was accepted")
            secureRelay.stop(); proxy.extensionOverride(nil)
        }
        let restored = BrowserProxy(defaults: defaults, password: "fixture-password", savePassword: { _ in })
        try require(restored.value == value, "configuration did not persist")
        let future = WKWebsiteDataStore.nonPersistent(); restored.attach(future)
        try require(future.proxyConfigurations.count == 1, "future store missed configuration")
        let failed = BrowserProxy(defaults: defaults, password: "", savePassword: { _ in throw NSError(domain: "fixture keychain failure", code: 1) })
        do { try failed.save(.init(), password: ""); throw NSError(domain: "failed keychain save accepted", code: 1) }
        catch { try require(failed.value == value, "failed save changed active configuration") }
        try proxy.save(.init(), password: "")
        let config = WKWebViewConfiguration(); config.websiteDataStore = privateStore
        let blocked = WKWebView(frame: .zero, configuration: config)
        let nav = Navigation()
        try await Task.sleep(for: .milliseconds(300))
        // Loopback destinations are exempt from Network's proxy configuration.
        // Establish that this public origin works directly before blocking it.
        try await nav.load(URL(string: "http://example.com/?direct=\(UUID())")!, in: blocked)
        var unreachable = value; unreachable.port = "1"
        try proxy.save(unreachable, password: "fixture-password")
        var rejected = false
        do { try await nav.load(URL(string: "http://example.com/?blocked=\(UUID())")!, in: blocked) }
        catch { rejected = true }
        try require(rejected, "unreachable proxy fell back to a direct origin")
        try proxy.save(.init(), password: "")
        try require(ordinary.proxyConfigurations.isEmpty && privateStore.proxyConfigurations.isEmpty, "system reset retained proxy")
        try await nav.load(URL(string: "http://127.0.0.1:\(port)/direct-origin")!, in: blocked)
        let direct = try await blocked.evaluateJavaScript("document.body.innerText") as? String ?? ""
        try require(direct.contains("DIRECT ORIGIN"), "system reset did not restore direct traffic")
    }
}
