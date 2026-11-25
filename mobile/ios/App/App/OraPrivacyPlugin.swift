import Foundation
import Capacitor
import UIKit

/**
 * App-switcher / screen-capture privacy for sensitive screens (a document
 * being signed, the app lock and PIN screens) — the iOS counterpart of
 * OraPrivacyPlugin.java (FLAG_SECURE).
 *
 * iOS has no public API to block screenshots. What it does allow:
 *  - the snapshot iOS takes for the app switcher is taken right after
 *    `willResignActive`; while `secure` is on, a plain overlay in the app's
 *    launch colour covers the window at that moment, so the switcher shows
 *    the overlay instead of the document. It is removed on `didBecomeActive`.
 *  - while the screen is being recorded / mirrored (`UIScreen.isCaptured`)
 *    and `secure` is on, the same overlay hides the content.
 *
 * The JS side (src/native/privacyScreen.ts) turns `secure` on while a
 * `data-sensitive-screen` element or a lock screen is shown, and also asks
 * for the background overlay whenever the app lock is enabled.
 */
@objc(OraPrivacyPlugin)
public class OraPrivacyPlugin: CAPPlugin, CAPBridgedPlugin {
    public let identifier = "OraPrivacyPlugin"
    public let jsName = "OraPrivacy"
    public let pluginMethods: [CAPPluginMethod] = [
        CAPPluginMethod(name: "setSecure", returnType: CAPPluginReturnPromise),
    ]

    private var secure = false
    private var overlay: UIView?
    private var observers: [NSObjectProtocol] = []

    override public func load() {
        let center = NotificationCenter.default
        observers.append(center.addObserver(forName: UIApplication.willResignActiveNotification, object: nil, queue: .main) { [weak self] _ in
            guard let self = self, self.secure else { return }
            self.showOverlay()
        })
        observers.append(center.addObserver(forName: UIApplication.didBecomeActiveNotification, object: nil, queue: .main) { [weak self] _ in
            guard let self = self else { return }
            if !(self.secure && UIScreen.main.isCaptured) {
                self.hideOverlay()
            }
        })
        observers.append(center.addObserver(forName: UIScreen.capturedDidChangeNotification, object: nil, queue: .main) { [weak self] _ in
            self?.applyCaptureState()
        })
    }

    deinit {
        observers.forEach { NotificationCenter.default.removeObserver($0) }
    }

    @objc func setSecure(_ call: CAPPluginCall) {
        let enabled = call.getBool("enabled") ?? false
        DispatchQueue.main.async {
            self.secure = enabled
            self.applyCaptureState()
            call.resolve()
        }
    }

    private func applyCaptureState() {
        if secure && UIScreen.main.isCaptured {
            showOverlay()
        } else if UIApplication.shared.applicationState == .active {
            hideOverlay()
        }
    }

    private func hostWindow() -> UIWindow? {
        if let window = bridge?.viewController?.view.window {
            return window
        }
        return UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap { $0.windows }
            .first { $0.isKeyWindow }
    }

    private func showOverlay() {
        guard overlay == nil, let window = hostWindow() else { return }
        let cover = UIView(frame: window.bounds)
        cover.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        // Launch-screen colour (capacitor.config.ts SplashScreen background).
        cover.backgroundColor = UIColor(red: 0x0B / 255.0, green: 0x12 / 255.0, blue: 0x20 / 255.0, alpha: 1)
        let label = UILabel()
        label.text = "OraSec"
        label.textColor = UIColor(white: 1, alpha: 0.9)
        label.font = UIFont.systemFont(ofSize: 28, weight: .semibold)
        label.translatesAutoresizingMaskIntoConstraints = false
        cover.addSubview(label)
        NSLayoutConstraint.activate([
            label.centerXAnchor.constraint(equalTo: cover.centerXAnchor),
            label.centerYAnchor.constraint(equalTo: cover.centerYAnchor),
        ])
        cover.isAccessibilityElement = false
        window.addSubview(cover)
        overlay = cover
    }

    private func hideOverlay() {
        overlay?.removeFromSuperview()
        overlay = nil
    }
}

