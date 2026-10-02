import Network
import Security
import Combine
import Foundation
import WebKit

struct ProxySettingsValue: Codable, Equatable {
    enum Mode: String, Codable, CaseIterable, Identifiable {
        case system, http, https, socks5
        var id: String { rawValue }
        var title: String {
            switch self {
            case .system: return "Disabled / System"
            case .http: return "HTTP"
            case .https: return "HTTPS"
            case .socks5: return "SOCKS5"
            }
        }
    }

    var mode: Mode = .system
    var host = ""
    var port = ""
    var username = ""

    var validation: String? {
        guard mode != .system else { return nil }
        let host = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !host.isEmpty, !host.contains(where: { $0.isWhitespace }),
              !host.contains("://"), !host.contains("/"), !host.contains("@") else {
            return "Enter a host name or IP address, without a URL or port."
        }
        guard let number = UInt16(port), number > 0 else {
            return "Enter a port from 1 to 65535."
        }
        return nil
    }

    func configurations(password: String) -> [ProxyConfiguration] {
        guard mode != .system, validation == nil, let number = UInt16(port) else { return [] }
        let endpoint = NWEndpoint.hostPort(
            host: .init(host.trimmingCharacters(in: .whitespacesAndNewlines)),
            port: .init(rawValue: number)!)
        var proxy: ProxyConfiguration
        switch mode {
        case .socks5: proxy = ProxyConfiguration(socksv5Proxy: endpoint)
        case .https: proxy = ProxyConfiguration(httpCONNECTProxy: endpoint, tlsOptions: .init())
        default: proxy = ProxyConfiguration(httpCONNECTProxy: endpoint)
        }
        // A failed explicit proxy must not silently send traffic directly.
        proxy.allowFailover = false
        if !username.isEmpty { proxy.applyCredential(username: username, password: password) }
        return [proxy]
    }
}

/// Stores are weakly held: a closed private tab must not keep its cookies alive.
@MainActor
final class BrowserProxy: ObservableObject {
    static let shared = BrowserProxy()
    @Published private(set) var value: ProxySettingsValue
    private var override: ProxyConfiguration?
    private var password: String
    private let defaults: UserDefaults
    private let savePassword: (String) throws -> Void
    private let stores = NSHashTable<WKWebsiteDataStore>.weakObjects()
    private static let key = "network.proxy"

    init(defaults: UserDefaults = Store.settings, password: String? = nil,
         savePassword: @escaping (String) throws -> Void = { try ProxySecret.write($0) }) {
        self.defaults = defaults
        self.savePassword = savePassword
        value = defaults.data(forKey: Self.key)
            .flatMap { try? JSONDecoder().decode(ProxySettingsValue.self, from: $0) } ?? .init()
        self.password = password ?? ProxySecret.read()
        // Visible launch can restore a page before extension workers are ready.
        // A persisted connected Nord profile starts blocked until its relay exists.
        if #available(macOS 15.4, *), defaults === Store.settings,
           Extensions.rememberedNordIsEnabled,
           (Extensions.settings(for: NordProxy.extensionID)["proxy.settings"] as? [String: Any])?["mode"] as? String == "pac_script" {
            var blocked = ProxyConfiguration(httpCONNECTProxy: .hostPort(host: "127.0.0.1", port: 9))
            blocked.allowFailover = false
            override = blocked
        }
    }

    func attach(_ store: WKWebsiteDataStore) {
        guard !stores.contains(store) else { return }
        stores.add(store)
        store.proxyConfigurations = override.map { [$0] } ?? value.configurations(password: password)
    }

    func extensionOverride(_ configuration: ProxyConfiguration?) {
        if configuration == nil && override == nil { return }
        override = configuration
        apply()
    }

    private func apply() {
        for store in stores.allObjects {
            store.proxyConfigurations = override.map { [$0] } ?? value.configurations(password: password)
        }
        // Otherwise CFNetwork can reuse a direct keep-alive connection after
        // the proxy changes. This terminates only this app's network process.
        if let store = stores.allObjects.first {
            let close = NSSelectorFromString("_terminateNetworkProcess")
            if store.responds(to: close) { store.perform(close) }
        }
    }

    func save(_ proposed: ProxySettingsValue, password: String) throws {
        guard override == nil else {
            throw NSError(domain: "SearchProxy", code: 2, userInfo: [NSLocalizedDescriptionKey: "NordVPN is controlling browsing routes. Disable the Nord extension before changing the manual proxy."])
        }
        if let message = proposed.validation {
            throw NSError(domain: "SearchProxy", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
        }
        let data = try JSONEncoder().encode(proposed)
        // Save the secret first; a keychain failure leaves the active setup alone.
        try savePassword(password)
        defaults.set(data, forKey: Self.key)
        self.password = password
        value = proposed
        apply()
    }

    var savedPassword: String { password }
}

private enum ProxySecret {
    private static var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: "Search.proxy" + (Store.world.map { ".\($0)" } ?? ""),
         kSecAttrAccount as String: "global"]
    }

    static func read() -> String {
        var query = query
        query[kSecReturnData as String] = true
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return "" }
        return String(data: data, encoding: .utf8) ?? ""
    }

    static func write(_ password: String) throws {
        let status: OSStatus
        if password.isEmpty {
            let removed = SecItemDelete(query as CFDictionary)
            status = removed == errSecItemNotFound ? errSecSuccess : removed
        } else {
            let attributes = [kSecValueData as String: Data(password.utf8)]
            let updated = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
            if updated == errSecItemNotFound {
                var item = query
                item.merge(attributes) { _, new in new }
                item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlocked
                status = SecItemAdd(item as CFDictionary, nil)
            } else { status = updated }
        }
        guard status == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status),
                          userInfo: [NSLocalizedDescriptionKey: "Could not save the proxy password in Keychain (\(status))."])
        }
    }
}
