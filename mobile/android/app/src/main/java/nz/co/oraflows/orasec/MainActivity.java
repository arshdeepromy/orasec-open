package nz.co.oraflows.orasec;

import android.content.res.Configuration;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.JavascriptInterface;
import android.webkit.WebView;

import androidx.activity.EdgeToEdge;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.getcapacitor.BridgeActivity;
import com.getcapacitor.WebViewListener;

import java.util.Locale;

/**
 * Publishes the real window insets to CSS, and registers the app's own
 * plugins (OraStatusBarPlugin, OraSecureStorePlugin, OraFilePlugin,
 * OraPrivacyPlugin). Ported from the publisher's invoicing app.
 *
 * Android's WebView maps env(safe-area-inset-*) to the display CUTOUT only —
 * never to the status or navigation bars. With targetSdk 35 the app draws edge
 * to edge, so on any device without a notch every inset resolves to 0 and
 * screen headers slide under the status bar (iOS is unaffected: there env()
 * covers the bars as well).
 *
 * Rather than dropping edge-to-edge, mirror the true insets into CSS custom
 * properties. index.css folds them into --safe-top/--safe-bot with max(), so
 * whichever platform reports a real value wins and neither double-counts.
 *
 * Keyboard: edge to edge (enforced from Android 15) the system no longer
 * resizes the window for the keyboard, and with Capacitor 8 the WebView kept
 * its full height - the keyboard simply covered the lower half of every form
 * and bottom sheet. The IME inset is therefore applied here as a bottom margin
 * on the WebView, so its viewport ends at the top of the keyboard (the page
 * scrolls the focused field into view as on Capacitor 7). While the keyboard
 * is up the bottom bar inset is published as 0: the WebView no longer reaches
 * the navigation bar.
 */
public class MainActivity extends BridgeActivity {

    /**
     * The last inset script, kept so it can be re-applied. The CSS variables
     * live on the page, so any page load (an OTA bundle switch, a reload after
     * a crash, a server change) wipes them while the window insets themselves
     * do not change and the listener does not fire again. Without re-applying,
     * the tab bar and sticky action bars sat on top of the 3-button
     * navigation bar after an update.
     */
    private volatile String lastInsetsJs = null;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        // Must precede super.onCreate(): Capacitor wires registered plugins into
        // the bridge as the WebView starts loading.
        registerPlugin(OraStatusBarPlugin.class);
        registerPlugin(OraSecureStorePlugin.class);
        registerPlugin(OraPrivacyPlugin.class);
        registerPlugin(OraFilePlugin.class);

        super.onCreate(savedInstanceState);

        // Android's WebView answers prefers-color-scheme: light even in the
        // system dark theme, so "Auto" never went dark (src/theme/systemTheme.ts).
        // Expose the real flag; the page reads it synchronously at start-up.
        // Added to the WebView before Capacitor's first navigation commits, and
        // re-registered pages (reloads, server switch) get it too.
        if (getBridge() != null && getBridge().getWebView() != null) {
            getBridge().getWebView().addJavascriptInterface(new SystemTheme(), "OraSystemTheme");
        }

        // Draw edge to edge on every Android version, not only where Android 15+
        // enforces it, so every device gets the same layout (the insets below are
        // published to CSS either way). Before this, Android 7-14 showed the
        // status- and navigation-bar insets twice: an empty band above the header
        // and another below the tab bar. Uses androidx's backward-compatible
        // EdgeToEdge rather than the deprecated Window bar-colour APIs, after
        // super.onCreate() so Capacitor has switched to the app theme.
        EdgeToEdge.enable(this);

        publishWindowInsets();

        if (getBridge() != null) {
            getBridge().addWebViewListener(new WebViewListener() {
                @Override
                public void onPageCommitVisible(WebView view, String url) {
                    reapplyInsets(view);
                }

                @Override
                public void onPageLoaded(WebView webView) {
                    reapplyInsets(webView);
                }
            });
        }
    }

    @Override
    public void onResume() {
        super.onResume();
        // Navigation mode can change while the app is in the background
        // (gestures <-> buttons, rotation); ask for fresh insets every time.
        ViewCompat.requestApplyInsets(getWindow().getDecorView());
        final WebView webView = getBridge() != null ? getBridge().getWebView() : null;
        if (webView != null) {
            reapplyInsets(webView);
        }
    }

    /** Night-mode flag for the page (see onCreate). */
    private final class SystemTheme {
        @JavascriptInterface
        public boolean isNight() {
            return isNightMode();
        }
    }

    private boolean isNightMode() {
        int mode = getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK;
        return mode == Configuration.UI_MODE_NIGHT_YES;
    }

    /** uiMode is in the activity's configChanges, so a theme switch lands here instead of recreating it. */
    @Override
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
        final WebView webView = getBridge() != null ? getBridge().getWebView() : null;
        if (webView != null) {
            final boolean night = (newConfig.uiMode & Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES;
            webView.post(() -> webView.evaluateJavascript(
                    "window.dispatchEvent(new CustomEvent('ora:system-theme',{detail:" + night + "}))", null));
        }
    }

    private void reapplyInsets(final WebView webView) {
        final String js = lastInsetsJs;
        if (js != null && webView != null) {
            webView.post(() -> webView.evaluateJavascript(js, null));
        } else {
            ViewCompat.requestApplyInsets(getWindow().getDecorView());
        }
    }

    /**
     * How far the keyboard reaches into the WebView's container, in px. Uses
     * the window's visible display frame (whose bottom is the top of the
     * keyboard while it is shown) rather than trusting the IME inset alone,
     * so a container the platform has already shrunk is not lifted again.
     * Never more than the IME inset itself.
     */
    static int keyboardOverlap(View webView, int imeBottom) {
        if (imeBottom <= 0) {
            return 0;
        }
        View container = webView.getParent() instanceof View ? (View) webView.getParent() : webView;
        if (container.getHeight() <= 0) {
            return imeBottom; // not laid out yet: fall back to the inset
        }
        android.graphics.Rect visible = new android.graphics.Rect();
        container.getWindowVisibleDisplayFrame(visible);
        int[] boxLoc = new int[2];
        container.getLocationOnScreen(boxLoc);
        int boxBottom = boxLoc[1] + container.getHeight();
        if (visible.bottom <= 0 || visible.bottom >= boxBottom) {
            // Frame not reporting the keyboard (or no overlap): use the inset
            // only when the frame is clearly unusable.
            return visible.bottom <= 0 ? imeBottom : 0;
        }
        return Math.min(imeBottom, boxBottom - visible.bottom);
    }

    private void applyImeMargin(WebView webView) {
        WindowInsetsCompat now = ViewCompat.getRootWindowInsets(getWindow().getDecorView());
        int imeBottom = now != null && now.isVisible(WindowInsetsCompat.Type.ime())
                ? now.getInsets(WindowInsetsCompat.Type.ime()).bottom
                : 0;
        ViewGroup.LayoutParams lp = webView.getLayoutParams();
        if (!(lp instanceof ViewGroup.MarginLayoutParams)) {
            return;
        }
        ViewGroup.MarginLayoutParams mlp = (ViewGroup.MarginLayoutParams) lp;
        // Measure against the container with the current margin removed.
        int margin = keyboardOverlap(webView, imeBottom);
        if (mlp.bottomMargin != margin) {
            mlp.bottomMargin = margin;
            webView.setLayoutParams(mlp);
        }
    }

    private void publishWindowInsets() {
        final View root = getWindow().getDecorView();
        ViewCompat.setOnApplyWindowInsetsListener(root, (v, insets) -> {
            Insets bars = insets.getInsets(
                    WindowInsetsCompat.Type.systemBars()
                            | WindowInsetsCompat.Type.displayCutout());
            boolean imeVisible = insets.isVisible(WindowInsetsCompat.Type.ime());
            int imeBottom = imeVisible
                    ? insets.getInsets(WindowInsetsCompat.Type.ime()).bottom
                    : 0;

            // CSS works in density-independent pixels; the insets arrive in px.
            float density = getResources().getDisplayMetrics().density;
            if (density <= 0f) {
                density = 1f;
            }

            final String js = String.format(Locale.US,
                    "document.documentElement.style.setProperty('--android-inset-top','%.0fpx');"
                            + "document.documentElement.style.setProperty('--android-inset-bottom','%.0fpx');"
                            + "document.documentElement.style.setProperty('--android-inset-left','%.0fpx');"
                            + "document.documentElement.style.setProperty('--android-inset-right','%.0fpx');",
                    bars.top / density,
                    (imeVisible ? 0 : bars.bottom) / density,
                    bars.left / density,
                    bars.right / density);

            lastInsetsJs = js;
            final WebView webView = getBridge() != null ? getBridge().getWebView() : null;
            if (webView != null) {
                // Only lift by the part of the keyboard that actually overlaps
                // the WebView's container. Some OEM builds (seen on a Samsung)
                // still shrink the window for the keyboard themselves; adding
                // the full IME height on top left a keyboard-sized grey gap.
                // The window frame can lag the inset, so re-check shortly after.
                applyImeMargin(webView);
                webView.postDelayed(() -> applyImeMargin(webView), 150);
                webView.postDelayed(() -> applyImeMargin(webView), 450);
                webView.post(() -> webView.evaluateJavascript(js, null));
            }
            return insets;
        });

        // The shell already makes room for the keyboard by giving the WebView
        // a bottom margin equal to the IME inset (above). Recent Android
        // System WebView versions ALSO shrink their visual viewport when they
        // receive IME insets, so the page was lifted twice and a keyboard-
        // sized grey gap appeared between the content and the keyboard
        // (seen on a Samsung, Oct 2026). Hand the WebView its insets with the
        // IME part removed so exactly one mechanism applies.
        final WebView shellWebView = getBridge() != null ? getBridge().getWebView() : null;
        if (shellWebView != null) {
            ViewCompat.setOnApplyWindowInsetsListener(shellWebView, (v, insets) -> {
                WindowInsetsCompat withoutIme = new WindowInsetsCompat.Builder(insets)
                        .setInsets(WindowInsetsCompat.Type.ime(), Insets.NONE)
                        .build();
                return ViewCompat.onApplyWindowInsets(v, withoutIme);
            });
        }
    }
}
