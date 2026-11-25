import Foundation
import Capacitor
import QuickLook

/**
 * Opens a file the app wrote (a document PDF in the cache)
 * in Quick Look — the iOS counterpart of Android's OraFilePlugin
 * (ACTION_VIEW through the FileProvider). Quick Look shows the document full
 * screen with the system Share button (print, Save to Files, Mail, …).
 * Rejects with code NO_APP when Quick Look can't show the type, so the
 * caller falls back to the share sheet exactly as on Android.
 */
@objc(OraFilePlugin)
public class OraFilePlugin: CAPPlugin, CAPBridgedPlugin, QLPreviewControllerDataSource {
    public let identifier = "OraFilePlugin"
    public let jsName = "OraFile"
    public let pluginMethods: [CAPPluginMethod] = [
        CAPPluginMethod(name: "open", returnType: CAPPluginReturnPromise),
    ]

    private var previewURL: URL?

    @objc func open(_ call: CAPPluginCall) {
        guard let uriString = call.getString("uri"), !uriString.isEmpty,
              let url = URL(string: uriString), url.isFileURL else {
            call.reject("uri is required")
            return
        }
        guard FileManager.default.fileExists(atPath: url.path) else {
            call.reject("file not found")
            return
        }
        DispatchQueue.main.async {
            guard QLPreviewController.canPreview(url as QLPreviewItem) else {
                call.reject("no_app", "NO_APP")
                return
            }
            guard let presenter = self.bridge?.viewController else {
                call.reject("no view controller")
                return
            }
            self.previewURL = url
            let preview = QLPreviewController()
            preview.dataSource = self
            presenter.present(preview, animated: true)
            call.resolve()
        }
    }

    public func numberOfPreviewItems(in controller: QLPreviewController) -> Int {
        return previewURL == nil ? 0 : 1
    }

    public func previewController(_ controller: QLPreviewController, previewItemAt index: Int) -> QLPreviewItem {
        return (previewURL ?? URL(fileURLWithPath: "/")) as QLPreviewItem
    }
}
