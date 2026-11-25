import Foundation
import Capacitor
import Security

/**
 * Keychain storage for the app's secrets on iOS: the OraSec session
 * token, the app PIN record and the Face ID / Touch ID switch (ported from the publisher's invoicing app).
 *
 * Why not Capacitor Preferences (UserDefaults): UserDefaults and the web
 * view's storage go into iCloud / Finder backups and move to a new iPhone
 * with Quick Start, so a restored or migrated phone would come back signed
 * in. Android uses a Keystore-sealed store (OraSecureStorePlugin.java) and
 * keeps it out of backups (res/xml/data_extraction_rules.xml). Here every
 * item is kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly: readable once the
 * phone has been unlocked after a restart, never synced to iCloud Keychain and
 * never restored onto another device.
 *
 * Keychain items survive an uninstall, UserDefaults do not. resetAfterReinstall()
 * runs before the web view loads and wipes this app's items on the first launch
 * of a fresh install, so a reinstall starts signed out with no PIN.
 */
@objc(OraSecureStorePlugin)
public class OraSecureStorePlugin: CAPPlugin, CAPBridgedPlugin {
    public let identifier = "OraSecureStorePlugin"
    public let jsName = "OraSecureStore"
    public let pluginMethods: [CAPPluginMethod] = [
        CAPPluginMethod(name: "get", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "set", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "remove", returnType: CAPPluginReturnPromise),
    ]

    static let service = "nz.co.oraflows.orasec.secure"
    private static let installMarker = "ora.secureStore.installed.v1"

    /// Wipe Keychain items left by a previous install (see the class comment).
    static func resetAfterReinstall() {
        let defaults = UserDefaults.standard
        guard !defaults.bool(forKey: installMarker) else { return }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ]
        SecItemDelete(query as CFDictionary)
        defaults.set(true, forKey: installMarker)
    }

    private func itemQuery(_ key: String) -> [String: Any] {
        return [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: OraSecureStorePlugin.service,
            kSecAttrAccount as String: key,
        ]
    }

    private func key(from call: CAPPluginCall) -> String? {
        guard let key = call.getString("key"), !key.isEmpty, key.count <= 128 else {
            call.reject("key is required")
            return nil
        }
        return key
    }

    @objc func get(_ call: CAPPluginCall) {
        guard let key = key(from: call) else { return }
        var query = itemQuery(key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            call.resolve(["value": NSNull()])
        } else if status == errSecSuccess, let data = result as? Data, let value = String(data: data, encoding: .utf8) {
            call.resolve(["value": value])
        } else {
            call.reject("Keychain read failed", String(status))
        }
    }

    @objc func set(_ call: CAPPluginCall) {
        guard let key = key(from: call) else { return }
        guard let value = call.getString("value") else {
            call.reject("value is required")
            return
        }
        let attributes: [String: Any] = [
            kSecValueData as String: Data(value.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        var status = SecItemUpdate(itemQuery(key) as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var add = itemQuery(key)
            add.merge(attributes) { _, new in new }
            status = SecItemAdd(add as CFDictionary, nil)
        }
        if status == errSecSuccess {
            call.resolve()
        } else {
            call.reject("Keychain write failed", String(status))
        }
    }

    @objc func remove(_ call: CAPPluginCall) {
        guard let key = key(from: call) else { return }
        let status = SecItemDelete(itemQuery(key) as CFDictionary)
        if status == errSecSuccess || status == errSecItemNotFound {
            call.resolve()
        } else {
            call.reject("Keychain delete failed", String(status))
        }
    }
}
