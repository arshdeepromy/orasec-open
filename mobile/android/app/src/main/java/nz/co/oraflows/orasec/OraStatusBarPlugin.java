package nz.co.oraflows.orasec;

import android.app.Activity;

import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsControllerCompat;

import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

/**
 * Status-bar appearance, because @capacitor/status-bar cannot do it here.
 *
 * On Android 15 (targetSdk 35) the system bars are always transparent and
 * `StatusBar.setStyle()` from @capacitor/status-bar is a no-op — verified on an
 * API 35 emulator, where the clock and signal icons stayed white on every light
 * screen and were effectively invisible.
 *
 * This is a real Capacitor plugin rather than a WebView JavascriptInterface on
 * purpose: Capacitor registers plugins *before* the page loads, whereas
 * `addJavascriptInterface` after `super.onCreate()` lands too late for the
 * already-loading document and needs a reload to take effect.
 */
@CapacitorPlugin(name = "OraStatusBar")
public class OraStatusBarPlugin extends Plugin {

    /**
     * `light` is true when the app is painting a LIGHT surface, which needs
     * dark status-bar content to stay legible.
     */
    @PluginMethod
    public void setLightSurface(PluginCall call) {
        final boolean light = Boolean.TRUE.equals(call.getBoolean("light", Boolean.TRUE));
        final Activity activity = getActivity();
        if (activity == null) {
            call.resolve();
            return;
        }

        activity.runOnUiThread(() -> {
            WindowInsetsControllerCompat controller = WindowCompat.getInsetsController(
                    activity.getWindow(), activity.getWindow().getDecorView());
            // "AppearanceLightBars" describes the BAR's own background, so it is
            // true exactly when the app surface behind it is light.
            controller.setAppearanceLightStatusBars(light);
            controller.setAppearanceLightNavigationBars(light);
        });

        call.resolve();
    }
}

