package nz.co.oraflows.orasec;

import android.app.Activity;
import android.view.WindowManager;

import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

/**
 * Screenshot / screen-recording / app-switcher protection for sensitive
 * screens (a document being signed, the app lock and PIN screens).
 *
 * On Android one flag does all three: FLAG_SECURE makes the window's content
 * black in screenshots, screen recordings, casting to non-secure displays and
 * the recent-apps thumbnail. The JS side (src/native/privacyScreen.ts) turns
 * it on while a `data-sensitive-screen` element or a lock screen is shown and
 * off again afterwards, so ordinary screens can still be screenshotted.
 *
 * The iOS counterpart (OraPrivacyPlugin.swift) covers the app-switcher
 * snapshot with an overlay; iOS has no public API to block screenshots.
 */
@CapacitorPlugin(name = "OraPrivacy")
public class OraPrivacyPlugin extends Plugin {

    @PluginMethod
    public void setSecure(PluginCall call) {
        final boolean enabled = Boolean.TRUE.equals(call.getBoolean("enabled", Boolean.FALSE));
        final Activity activity = getActivity();
        if (activity == null) {
            call.resolve();
            return;
        }
        activity.runOnUiThread(() -> {
            if (enabled) {
                activity.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
            } else {
                activity.getWindow().clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
            }
        });
        call.resolve();
    }
}

