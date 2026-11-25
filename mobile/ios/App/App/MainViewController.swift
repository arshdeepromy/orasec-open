import UIKit
import Capacitor

/**
 * The app's bridge view controller (SceneDelegate + Main.storyboard). Registers
 * the app's own iOS plugins — the counterparts of the Android ones registered
 * in MainActivity.java. Android-only plugins (OraStatusBar, OraPush) have no
 * iOS version: the JS side handles iOS without them.
 */
class MainViewController: CAPBridgeViewController {
    override open func capacitorDidLoad() {
        // Before any JS runs: a fresh install must not see a previous
        // install's Keychain items (session token, PIN record).
        OraSecureStorePlugin.resetAfterReinstall()
        bridge?.registerPluginInstance(OraSecureStorePlugin())
        bridge?.registerPluginInstance(OraFilePlugin())
        bridge?.registerPluginInstance(OraPrivacyPlugin())
    }
}

