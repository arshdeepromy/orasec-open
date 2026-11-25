package nz.co.oraflows.orasec;

import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.net.Uri;

import androidx.core.content.FileProvider;

import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.io.File;

/**
 * Opens a file the app wrote (e.g. a signed document PDF in the cache directory) in
 * the user's default viewer.
 *
 * Android's WebView cannot preview PDFs and ignores `<a download>` / blob
 * `window.open`, so without this the PDF screens were dead ends. The file is
 * handed over through the app's FileProvider (see res/xml/file_paths.xml),
 * never as a raw file:// URI, which Android 7+ refuses to share.
 */
@CapacitorPlugin(name = "OraFile")
public class OraFilePlugin extends Plugin {

    @PluginMethod
    public void open(PluginCall call) {
        String uriString = call.getString("uri");
        String mimeType = call.getString("mimeType", "application/pdf");
        if (uriString == null || uriString.isEmpty()) {
            call.reject("uri is required");
            return;
        }
        try {
            String path = Uri.parse(uriString).getPath();
            if (path == null) {
                call.reject("invalid uri");
                return;
            }
            File file = new File(path);
            Uri contentUri = FileProvider.getUriForFile(
                    getContext(), getContext().getPackageName() + ".fileprovider", file);

            Intent intent = new Intent(Intent.ACTION_VIEW);
            intent.setDataAndType(contentUri, mimeType);
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_ACTIVITY_NEW_TASK);
            getActivity().startActivity(intent);
            call.resolve();
        } catch (ActivityNotFoundException e) {
            call.reject("no_app", "NO_APP");
        } catch (Exception e) {
            call.reject(e.getMessage() != null ? e.getMessage() : "open failed");
        }
    }
}
