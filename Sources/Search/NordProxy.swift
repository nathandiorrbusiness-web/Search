import CFNetwork
import Foundation
import Network
import WebKit

/// Nord 6.1.1 uses host-based PAC rules. A loopback CONNECT relay evaluates
/// those rules per destination; WebKit's public proxy API cannot execute PAC.
/// Credentials come only from the controlling extension over native messages.
@available(macOS 15.4, *)
@MainActor
final class NordProxy {
    static let shared = NordProxy()
    static let extensionID = "fjoaledfpmneenckfbpdfhkmimnjocfa"
    nonisolated static let shim = #"""
      // Nord's blocking authentication callback is answered over a browser-owned
      // channel. It never goes through website runtime messages or a global event.
      if (background && runtime.id === "fjoaledfpmneenckfbpdfhkmimnjocfa") {
        const auth = new Map(), observations = { completed: new Map(), failed: new Map() };
        // This version's handlers use <all_urls>. Refuse other filters rather
        // than deliver synthetic events with broader reach than requested.
        const supported = (filter) => filter && Array.isArray(filter.urls) && filter.urls.length === 1 && filter.urls[0] === "<all_urls>" && Object.keys(filter).every(k => k === "urls");
        const required = chrome.webRequest.onAuthRequired || event();
        put(required, "addListener", (listener, filter, options) => {
          if (!supported(filter)) throw new Error("Nord native auth requires an all-URLs filter");
          if (typeof listener === "function") auth.set(listener, { filter, options });
        });
        put(required, "removeListener", (listener) => auth.delete(listener));
        put(required, "hasListener", (listener) => auth.has(listener));
        put(required, "hasListeners", () => auth.size > 0);
        put(chrome.webRequest, "onAuthRequired", required);
        for (const [name, key] of [["onCompleted", "completed"], ["onErrorOccurred", "failed"]]) {
          const ev = chrome.webRequest[name];
          if (!ev) continue;
          const add = ev.addListener.bind(ev), remove = ev.removeListener.bind(ev);
          put(ev, "addListener", (listener, filter, options) => {
            if (supported(filter)) observations[key].set(listener, filter); return add(listener, filter, options);
          });
          put(ev, "removeListener", (listener) => { observations[key].delete(listener); return remove(listener); });
        }
        const handle = (message) => {
          if (!message) return;
          if (message.auth) {
            const listener = auth.entries().next().value;
            const finish = (result) => native("nord.answer", [message.auth, result || {}]).catch(() => {});
            if (!listener) return finish({ cancel: true });
            let answered = false;
            const done = (result) => { if (!answered) { answered = true; finish(result); } };
            try {
              const result = listener[0](message.details, done);
              if (result && typeof result.then === "function") result.then(done, () => done({ cancel: true }));
              else if (result && typeof result === "object") done(result);
              else if (!(listener[1].options || []).includes("asyncBlocking")) done({});
            } catch (e) { done({ cancel: true }); }
          } else if (observations[message.event]) {
            for (const listener of [...observations[message.event].keys()]) { try { listener(message.details); } catch (e) {} }
          } else if (message.event === "changed") {
            for (const listener of chrome.proxy.settings.onChange.listeners) { try { listener({ value: message.value, levelOfControl: "controlled_by_this_extension" }); } catch (e) {} }
          } else if (message.event === "error") {
            for (const listener of chrome.proxy.onProxyError.listeners) { try { listener(message.details); } catch (e) {} }
          }
        };
        // WebKit workers do not reliably dispatch messages on native ports.
        // Search's one-shot native calls also work during worker startup.
        const receive = async () => {
          for (;;) {
            try {
              const message = await native("nord.receive", []);
              if (message && message.event === "stopped") return;
              handle(message);
            } catch (e) { await new Promise(resolve => setTimeout(resolve, 1000)); }
          }
        };
        receive();
      }
    """#
    private var relay: NordRelay?
    private var notifications: [[String: Any]] = []
    private var receiver: (id: UUID, done: CheckedContinuation<[String: Any], Never>)?
    private var lastReceive = Date.distantPast
    private weak var context: WKWebExtensionContext?
    private var waiting: [String: CheckedContinuation<[String: String], Error>] = [:]
    private var generation = UUID()
    private var receiverGeneration = UUID()
    private var transition = UUID()
    private var checkpoints: [String] = []
    var diagnostics: [String: Any] {
        ["checkpoints": checkpoints, "relay": relay != nil, "receiver": Date().timeIntervalSince(lastReceive) < 3,
         "pendingAuthentication": waiting.count]
    }
    private func note(_ checkpoint: String) {
        checkpoints.append(checkpoint)
        checkpoints = Array(checkpoints.suffix(40))
    }

    func set(_ value: [String: Any], context: WKWebExtensionContext) async throws {
        let operation = UUID(); transition = operation
        note("settings-start")
        do {
            try await apply(value, context: context, operation: operation)
            note("settings-applied")
        } catch {
            note("settings-failed")
            throw error
        }
    }

    private func apply(_ value: [String: Any], context: WKWebExtensionContext, operation: UUID) async throws {
        guard context.uniqueIdentifier == Self.extensionID,
              context.webExtension.manifest["version"] as? String == "6.1.1" else {
            throw failure("Proxy extensions require native support; this build supports NordVPN 6.1.1.")
        }
        if self.context !== context {
            receiverGeneration = UUID()
            cancelPending()
            let stopped = receiver?.done; receiver = nil
            notifications.removeAll()
            lastReceive = .distantPast
            stopped?.resume(returning: ["event": "stopped"])
        }
        self.context = context
        let mode = value["mode"] as? String ?? "system"
        let script: String
        if mode == "system" || mode == "direct" { script = "function FindProxyForURL() { return 'DIRECT'; }" }
        else {
            guard mode == "pac_script", let pac = value["pacScript"] as? [String: Any],
                  let data = pac["data"] as? String, data.utf8.count <= 262_144 else {
                throw failure("Nord proxy routing requires an inline PAC script.")
            }
            script = data
        }
        // Reject malformed/unsupported routes before reporting settings.set success.
        _ = try await Task.detached { try NordRoute.evaluate(script, host: "search-proxy-check.invalid", port: 443) }.value
        guard transition == operation else { throw CancellationError() }
        if let relay {
            cancelPending()
            relay.update(script: script)
            post(["event": "changed", "value": value])
            return
        }
        let made = try await NordRelay.start(script: script) { [weak self] host, port, destination in
            guard let self else { throw failure("Nord proxy controller closed.") }
            self.note("auth-request")
            do {
                let credentials = try await self.credentials(host: host, port: port, destination: destination)
                self.note("auth-answered")
                return credentials
            } catch {
                self.note("auth-failed")
                throw error
            }
        }
        made.onDiagnostic = { [weak self] checkpoint in self?.note(checkpoint) }
        guard transition == operation else { made.stop(); throw CancellationError() }
        made.onFailure = { [weak self, weak made] error in
            guard let self, let made, self.relay === made else { return }
            self.post(["event": "error", "details": ["fatal": true, "error": "Nord proxy listener failed", "details": error.localizedDescription]])
        }
        cancelPending()
        relay?.stop()
        relay = made
        BrowserProxy.shared.extensionOverride(made.configuration)
        post(["event": "changed", "value": value])
    }

    func restore(_ context: WKWebExtensionContext) async {
        guard context.uniqueIdentifier == Self.extensionID else { return }
        let value = Extensions.settings(for: Self.extensionID)["proxy.settings"] as? [String: Any] ?? ["mode": "system"]
        let operation = UUID(); transition = operation
        do { try await apply(value, context: context, operation: operation) }
        catch {
            guard transition == operation else { return }
            // A remembered Secured state may not become direct on a restore failure.
            var blocked = ProxyConfiguration(httpCONNECTProxy: .hostPort(host: "127.0.0.1", port: 9))
            blocked.allowFailover = false
            BrowserProxy.shared.extensionOverride(blocked)
            post(["event": "error", "details": ["fatal": true, "error": "Nord proxy restore failed", "details": error.localizedDescription]])
        }
    }

    func stop() {
        transition = UUID()
        receiverGeneration = UUID()
        context = nil
        lastReceive = .distantPast
        let stopped = receiver?.done; receiver = nil
        notifications.removeAll()
        stopped?.resume(returning: ["event": "stopped"])
        cancelPending()
        relay?.stop(); relay = nil
        BrowserProxy.shared.extensionOverride(nil)
        post(["event": "changed", "value": ["mode": "system"]])
    }

    private func authorize(_ context: WKWebExtensionContext) throws {
        guard context.uniqueIdentifier == Self.extensionID, context.isLoaded,
              context.webExtension.manifest["version"] as? String == "6.1.1",
              context === self.context,
              ExtensionShims.allowed(Self.extensionID, context: context).contains("proxy"),
              ExtensionShims.allowed(Self.extensionID, context: context).contains("webRequest") else {
            throw failure("Only Nord's authorized context may use the Nord authentication channel.")
        }
    }

    func receive(_ context: WKWebExtensionContext) async throws -> [String: Any] {
        try authorize(context)
        guard receiver == nil else { throw failure("Nord already has a pending receive.") }
        lastReceive = Date()
        if !notifications.isEmpty { return notifications.removeFirst() }
        let id = UUID(), turn = receiverGeneration
        let message: [String: Any] = await withCheckedContinuation { done in
            receiver = (id, done)
            Task { [weak self] in
                try? await Task.sleep(for: .seconds(1))
                guard let self, self.receiver?.id == id else { return }
                let done = self.receiver?.done; self.receiver = nil
                done?.resume(returning: ["event": "idle"])
            }
        }
        try authorize(context)
        // Route changes cancel credentials, but their notifications still
        // belong to this receiver. Only stop/context replacement invalidates it.
        guard receiverGeneration == turn else { throw failure("Nord receiver changed.") }
        return message
    }

    func answer(_ token: String, result: [String: Any], context: WKWebExtensionContext) throws {
        try authorize(context)
        guard let done = waiting.removeValue(forKey: token) else { return }
        guard result["cancel"] as? Bool != true,
              let auth = result["authCredentials"] as? [String: String],
              let username = auth["username"], let password = auth["password"],
              !username.isEmpty, !password.isEmpty else {
            note(result["cancel"] as? Bool == true ? "auth-reply-cancel" : "auth-reply-empty")
            done.resume(throwing: failure("Nord declined proxy authentication.")); return
        }
        done.resume(returning: ["username": username, "password": password, "requestID": token])
    }

    private func credentials(host: String, port: UInt16, destination: String) async throws -> [String: String] {
        let turn = generation
        if Date().timeIntervalSince(lastReceive) >= 3, let context, context.isLoaded {
            Task { [weak context] in try? await context?.loadBackgroundContent() }
        }
        // The worker can be starting while its first PAC setting is applied.
        for _ in 0..<50 {
            if Date().timeIntervalSince(lastReceive) < 3 { break }
            try await Task.sleep(for: .milliseconds(100))
            guard generation == turn else { throw failure("Nord proxy changed.") }
        }
        guard Date().timeIntervalSince(lastReceive) < 3, waiting.count < 128 else { throw failure("Nord authentication is unavailable.") }
        let token = UUID().uuidString
        return try await withTaskCancellationHandler {
          try await withCheckedThrowingContinuation { continuation in
            guard !Task.isCancelled else { continuation.resume(throwing: CancellationError()); return }
            waiting[token] = continuation
            post(["auth": token, "details": ["requestId": token, "url": destination, "method": "GET", "type": "other", "tabId": -1,
                 "timeStamp": Date().timeIntervalSince1970 * 1000, "isProxy": true,
                 "scheme": "basic", "realm": "NordVPN", "challenger": ["host": host, "port": Int(port)],
                 "statusCode": 407, "statusLine": "HTTP/1.1 407 Proxy Authentication Required", "responseHeaders": []]])
            Task { [weak self] in
                try? await Task.sleep(for: .seconds(10))
                if let done = self?.waiting.removeValue(forKey: token) {
                    self?.note("auth-timeout")
                    done.resume(throwing: failure("Nord authentication timed out."))
                }
            }
          }
        } onCancel: {
            Task { @MainActor [weak self] in
                self?.waiting.removeValue(forKey: token)?.resume(throwing: CancellationError())
            }
        }
    }

    func completed(_ id: String, url: String, error: String? = nil) {
        post(["event": error == nil ? "completed" : "failed", "details": ["requestId": id, "url": url, "tabId": -1, "type": "other", "error": error ?? "", "timeStamp": Date().timeIntervalSince1970 * 1000]])
    }

    private func cancelPending() {
        generation = UUID()
        let old = waiting; waiting.removeAll()
        for done in old.values { done.resume(throwing: failure("Nord proxy changed.")) }
    }
    private func post(_ data: [String: Any]) {
        guard context != nil else { return }
        if let ready = receiver?.done {
            receiver = nil
            ready.resume(returning: data)
        } else if notifications.count < 512 {
            notifications.append(data)
        } else {
            // A stalled worker cannot accumulate messages or leave routing
            // active without authentication and completion delivery.
            notifications = [["event": "error", "details": ["fatal": true,
                "error": "Nord authentication receiver stalled", "details": "Notification queue limit reached."]]]
            cancelPending()
            relay?.update(script: "function FindProxyForURL() { return 'PROXY localhost:0'; }")
            note("receiver-overflow-blocked")
        }
    }
}

private func failure(_ message: String) -> NSError {
    NSError(domain: "Search.NordProxy", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
}

struct NordRoute: Sendable {
    enum Kind: Sendable { case direct, blocked, http, https }
    var kind: Kind
    var host: String = ""
    var port: UInt16 = 0

    static func evaluate(_ script: String, host: String, port: UInt16) throws -> NordRoute {
        var parts = URLComponents(); parts.scheme = port == 80 ? "http" : "https"; parts.host = host; parts.port = Int(port); parts.path = "/"
        guard let url = parts.url else { throw failure("Invalid proxy destination.") }
        // CFNetwork does not recognize Chromium's HTTPS PAC directive. Its
        // kCFProxyTypeHTTPS means a plaintext PROXY for an HTTPS destination.
        // Preserve TLS selection using SOCKS as an internal result marker;
        // actual SOCKS and multi-route answers are refused by this wrapper.
        let wrapped = script + "\n" + #"""
        ;var __searchFindProxyForURL = FindProxyForURL;
        FindProxyForURL = function(url, host) {
            var route = __searchFindProxyForURL(url, host);
            if (typeof route !== "string" || route.indexOf(";") !== -1) return "SEARCH_UNSUPPORTED";
            route = route.trim();
            if (route === "DIRECT") return route;
            if (/^PROXY\s+[^\s]+$/.test(route)) return route;
            if (/^HTTPS\s+[^\s]+$/.test(route)) return route.replace(/^HTTPS\s+/, "SOCKS ");
            return "SEARCH_UNSUPPORTED";
        };
        """#
        var error: Unmanaged<CFError>?
        guard let answer = CFNetworkCopyProxiesForAutoConfigurationScript(wrapped as CFString, url as CFURL, &error)?.takeRetainedValue() as? [[String: Any]] else {
            throw error?.takeRetainedValue() ?? failure("PAC evaluation failed.")
        }
        guard answer.count == 1, let route = answer.first, let type = route[kCFProxyTypeKey as String] as? String else {
            throw failure("Nord PAC must select exactly one route without implicit failover.")
        }
        if type == kCFProxyTypeNone as String { return .init(kind: .direct) }
        if (type == kCFProxyTypeHTTP as String || type == kCFProxyTypeHTTPS as String), route[kCFProxyHostNameKey as String] as? String == "localhost",
           (route[kCFProxyPortNumberKey as String] as? NSNumber)?.intValue == 0 { return .init(kind: .blocked) }
        guard type == kCFProxyTypeHTTP as String || type == kCFProxyTypeHTTPS as String || type == kCFProxyTypeSOCKS as String,
              let name = route[kCFProxyHostNameKey as String] as? String, !name.isEmpty,
              let number = route[kCFProxyPortNumberKey as String] as? NSNumber,
              let port = UInt16(exactly: number.intValue), port > 0 else { throw failure("Unsupported Nord PAC route.") }
        return .init(kind: type == kCFProxyTypeSOCKS as String ? .https : .http, host: name, port: port)
    }

    func configuration(credentials: [String: String]) -> ProxyConfiguration? {
        guard kind != .direct else { return nil }
        var made = ProxyConfiguration(httpCONNECTProxy: .hostPort(host: .init(host), port: .init(rawValue: port)!), tlsOptions: kind == .https ? .init() : nil)
        made.allowFailover = false
        made.applyCredential(username: credentials["username"] ?? "", password: credentials["password"] ?? "")
        return made
    }
}

/// Only CONNECT is accepted, bounded headers, a random credential per listener,
/// and a loopback bind. Network.framework owns upstream CONNECT, TLS and auth.
@available(macOS 15.4, *)
@MainActor
final class NordRelay {
    private let listener: NWListener
    private var script: String
    private let auth: (String, UInt16, String) async throws -> [String: String]
    private let localSecret = UUID().uuidString
    private var connections: [UUID: Tunnel] = [:]
    private var starting: CheckedContinuation<Void, Error>?
    var onFailure: ((Error) -> Void)?
    var onDiagnostic: (String) -> Void = { _ in }
    var configuration: ProxyConfiguration {
        var made = ProxyConfiguration(httpCONNECTProxy: .hostPort(host: "127.0.0.1", port: listener.port!))
        made.allowFailover = false
        made.applyCredential(username: "Search", password: localSecret)
        return made
    }

    private init(script: String, auth: @escaping (String, UInt16, String) async throws -> [String: String]) throws {
        self.script = script; self.auth = auth
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: parameters)
    }
    static func start(script: String, auth: @escaping (String, UInt16, String) async throws -> [String: String]) async throws -> NordRelay {
        let made = try NordRelay(script: script, auth: auth)
        try await withCheckedThrowingContinuation { continuation in
            made.starting = continuation
            made.listener.stateUpdateHandler = { [weak made] state in
                MainActor.assumeIsolated {
                    guard let made else { return }
                    switch state {
                    case .ready: let done = made.starting; made.starting = nil; done?.resume()
                    case .failed(let error): let done = made.starting; made.starting = nil; done?.resume(throwing: error); made.onFailure?(error); made.stop()
                    default: break
                    }
                }
            }
            made.listener.newConnectionHandler = { [weak made] connection in
                MainActor.assumeIsolated {
                    guard let made, made.connections.count < 256 else { connection.cancel(); return }
                    let id = UUID()
                    let tunnel = Tunnel(client: connection, script: made.script, localSecret: made.localSecret, auth: made.auth)
                    made.connections[id] = tunnel
                    tunnel.onEnd = { [weak made] in made?.connections[id] = nil }
                    tunnel.onDiagnostic = { [weak made] checkpoint in made?.onDiagnostic(checkpoint) }
                    tunnel.start()
                }
            }
            made.listener.start(queue: .main)
            Task {
                try? await Task.sleep(for: .seconds(5))
                if let done = made.starting { made.starting = nil; done.resume(throwing: failure("Proxy listener timed out.")); made.stop() }
            }
        }
        return made
    }
    func update(script: String) {
        self.script = script
        // Keep WebKit's loopback endpoint stable: replacing its network
        // process during settings.set also kills the calling Nord worker.
        let old = connections; connections.removeAll()
        for tunnel in old.values { tunnel.end() }
    }
    func stop() {
        listener.cancel()
        let old = connections; connections.removeAll()
        for tunnel in old.values { tunnel.end() }
    }

    @MainActor
    final class Tunnel {
        let client: NWConnection
        let script: String
        let localSecret: String
        let auth: (String, UInt16, String) async throws -> [String: String]
        var upstream: NWConnection?
        var header = Data()
        var ended = false
        var ready = false
        var finishedDirections = 0
        var work: Task<Void, Never>?
        var onEnd: (() -> Void)?
        var onDiagnostic: (String) -> Void = { _ in }
        var onCompletion: (String, String, String?) -> Void = { NordProxy.shared.completed($0, url: $1, error: $2) }
        var requestID: String?
        var destination = ""
        init(client: NWConnection, script: String, localSecret: String, auth: @escaping (String, UInt16, String) async throws -> [String: String]) {
            self.client = client; self.script = script; self.localSecret = localSecret; self.auth = auth
        }
        func start() {
            client.start(queue: .main)
            readHeader()
            Task { [weak self] in
                try? await Task.sleep(for: .seconds(20))
                if self?.ready == false { self?.onDiagnostic("tunnel-timeout"); self?.report(error: "net::ERR_PROXY_CONNECTION_FAILED"); self?.end() }
            }
        }
        func readHeader() {
            client.receive(minimumIncompleteLength: 1, maximumLength: 8192) { [weak self] data, _, complete, error in
                MainActor.assumeIsolated {
                    guard let self, !self.ended else { return }
                    if let data { self.header.append(data) }
                    guard self.header.count <= 16_384, error == nil else { self.end(); return }
                    if let range = self.header.range(of: Data("\r\n\r\n".utf8)) {
                        // CONNECT's next bytes belong to the tunnel. Never discard them.
                        let pending = self.header.subdata(in: range.upperBound..<self.header.count)
                        let head = self.header.subdata(in: 0..<range.lowerBound)
                        self.open(head, pending: pending)
                    } else if complete { self.end() } else { self.readHeader() }
                }
            }
        }
        func open(_ data: Data, pending: Data) {
            let lines = String(decoding: data, as: UTF8.self).components(separatedBy: "\r\n")
            let first = (lines.first ?? "").split(separator: " ")
            guard first.count == 3, first[0] == "CONNECT", first[2] == "HTTP/1.1", let url = URL(string: "http://\(first[1])/"),
                  let host = url.host, let number = url.port, let port = UInt16(exactly: number), port > 0 else { reply(400); return }
            let expected = "Basic " + Data("Search:\(localSecret)".utf8).base64EncodedString()
            let credentials = lines.dropFirst().compactMap { line -> String? in
                let bits = line.split(separator: ":", maxSplits: 1)
                return bits.count == 2 && bits[0].lowercased() == "proxy-authorization" ? bits[1].trimmingCharacters(in: .whitespaces) : nil
            }
            guard credentials.count == 1, credentials[0] == expected else { reply(407); return }
            onDiagnostic("tunnel-received")
            destination = "\(port == 80 ? "http" : "https")://\(first[1])/"
            work = Task { [weak self] in
                guard let self else { return }
                do {
                    let script = self.script
                    let route = try await Task.detached { try NordRoute.evaluate(script, host: host, port: port) }.value
                    self.onDiagnostic(route.kind == .direct ? "route-direct" : route.kind == .blocked ? "route-blocked" : "route-proxy")
                    try Task.checkCancellation()
                    guard route.kind != .blocked else { throw failure("Nord kill switch blocked this destination.") }
                    let parameters = NWParameters.tcp
                    if route.kind != .direct {
                        let credentials = try await self.auth(route.host, route.port, self.destination)
                        self.requestID = credentials["requestID"]
                        try Task.checkCancellation()
                        let privacy = NWParameters.PrivacyContext(description: "Search Nord proxy")
                        privacy.proxyConfigurations = [route.configuration(credentials: credentials)!]
                        parameters.setPrivacyContext(privacy)
                    }
                    guard !self.ended else { return }
                    let connection = NWConnection(host: .init(host), port: .init(rawValue: port)!, using: parameters)
                    self.upstream = connection
                    connection.stateUpdateHandler = { [weak self] state in
                        MainActor.assumeIsolated {
                            guard let self, !self.ended else { return }
                            switch state {
                            case .ready:
                                self.onDiagnostic("upstream-ready")
                                self.ready = true
                                self.client.send(content: Data("HTTP/1.1 200 Connection Established\r\n\r\n".utf8), completion: .contentProcessed { [weak self] error in
                                    MainActor.assumeIsolated {
                                        guard let self, error == nil else { self?.end(); return }
                                        let begin = {
                                            self.pipe(self.client, to: connection); self.pipe(connection, to: self.client)
                                        }
                                        if pending.isEmpty { begin() }
                                        else { connection.send(content: pending, completion: .contentProcessed { [weak self] error in
                                            MainActor.assumeIsolated { if error == nil { begin() } else { self?.end() } }
                                        }) }
                                    }
                                })
                            case .failed: self.onDiagnostic("upstream-failed"); self.report(error: "net::ERR_PROXY_CONNECTION_FAILED"); self.reply(502)
                            case .cancelled: self.end()
                            default: break
                            }
                        }
                    }
                    connection.start(queue: .main)
                } catch { self.onDiagnostic("tunnel-failed"); self.report(error: "net::ERR_PROXY_CONNECTION_FAILED"); self.reply(502) }
            }
        }
        func pipe(_ source: NWConnection, to target: NWConnection) {
            source.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, complete, error in
                MainActor.assumeIsolated {
                    guard let self, !self.ended, error == nil else { self?.end(); return }
                    target.send(content: data, contentContext: complete ? .finalMessage : .defaultMessage, isComplete: complete, completion: .contentProcessed { [weak self] error in
                        MainActor.assumeIsolated {
                            guard let self, !self.ended, error == nil else { self?.end(); return }
                            if complete {
                                self.finishedDirections += 1
                                if self.finishedDirections == 2 { self.end(error: nil) }
                            } else { self.pipe(source, to: target) }
                        }
                    })
                }
            }
        }
        func reply(_ status: Int) {
            guard !ended else { return }
            let name = status == 407 ? "Proxy Authentication Required" : "Proxy Error"
            let auth = status == 407 ? "Proxy-Authenticate: Basic realm=\"Search\"\r\n" : ""
            client.send(content: Data("HTTP/1.1 \(status) \(name)\r\n\(auth)Content-Length: 0\r\nConnection: close\r\n\r\n".utf8), completion: .contentProcessed { [weak self] _ in MainActor.assumeIsolated { self?.end() } })
        }
        func report(error: String? = nil) {
            if let requestID { onCompletion(requestID, destination, error); self.requestID = nil }
        }
        func end(error: String? = "net::ERR_ABORTED") {
            guard !ended else { return }; ended = true
            report(error: error)
            work?.cancel(); client.cancel(); upstream?.cancel(); onEnd?()
        }
    }
}
