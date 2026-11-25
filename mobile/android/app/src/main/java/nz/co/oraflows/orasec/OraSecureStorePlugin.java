package nz.co.oraflows.orasec;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Secret storage for the app on Android: the OraSec session token (and any
 * other small secret the JS side asks for). Counterpart of the iOS
 * OraSecureStorePlugin.swift (Keychain).
 *
 * Every value is encrypted with an AES-256-GCM key that lives in the Android
 * Keystore (hardware-backed where the device has it) and never leaves it; only
 * the ciphertext + IV are written to the app's private SharedPreferences file
 * "OraSecureStore". The file is also kept out of backups and device transfer
 * (android:allowBackup="false", res/xml/data_extraction_rules.xml), and a
 * Keystore key is never exported, so a copied file is useless on another
 * device.
 *
 * Capacitor Preferences (the plain CapacitorStorage.xml file) is NOT used for
 * secrets any more; src/api/session.ts migrates an old token once.
 */
@CapacitorPlugin(name = "OraSecureStore")
public class OraSecureStorePlugin extends Plugin {

    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String KEY_ALIAS = "nz.co.oraflows.orasec.secure.v1";
    private static final String PREFS = "OraSecureStore";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_BITS = 128;
    private static final int MAX_KEY_LENGTH = 128;

    private SharedPreferences prefs() {
        return getContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private static synchronized SecretKey secretKey() throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE);
        ks.load(null);
        KeyStore.Entry entry = ks.getEntry(KEY_ALIAS, null);
        if (entry instanceof KeyStore.SecretKeyEntry) {
            return ((KeyStore.SecretKeyEntry) entry).getSecretKey();
        }
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);
        generator.init(new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build());
        return generator.generateKey();
    }

    static String encrypt(String plain) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey());
        byte[] iv = cipher.getIV();
        byte[] sealed = cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8));
        return Base64.encodeToString(iv, Base64.NO_WRAP) + ":" + Base64.encodeToString(sealed, Base64.NO_WRAP);
    }

    static String decrypt(String stored) throws Exception {
        int sep = stored.indexOf(':');
        if (sep <= 0) {
            throw new IllegalArgumentException("malformed");
        }
        byte[] iv = Base64.decode(stored.substring(0, sep), Base64.NO_WRAP);
        byte[] sealed = Base64.decode(stored.substring(sep + 1), Base64.NO_WRAP);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey(), new GCMParameterSpec(GCM_TAG_BITS, iv));
        return new String(cipher.doFinal(sealed), StandardCharsets.UTF_8);
    }

    private String key(PluginCall call) {
        String key = call.getString("key");
        if (key == null || key.isEmpty() || key.length() > MAX_KEY_LENGTH) {
            call.reject("key is required");
            return null;
        }
        return key;
    }

    @PluginMethod
    public void get(PluginCall call) {
        String key = key(call);
        if (key == null) {
            return;
        }
        JSObject ret = new JSObject();
        String stored = prefs().getString(key, null);
        if (stored == null) {
            ret.put("value", JSObject.NULL);
            call.resolve(ret);
            return;
        }
        try {
            ret.put("value", decrypt(stored));
        } catch (Exception e) {
            // The Keystore key is gone (e.g. the user cleared credentials) or
            // the entry is corrupt: the secret is unrecoverable, forget it.
            prefs().edit().remove(key).apply();
            ret.put("value", JSObject.NULL);
        }
        call.resolve(ret);
    }

    @PluginMethod
    public void set(PluginCall call) {
        String key = key(call);
        if (key == null) {
            return;
        }
        String value = call.getString("value");
        if (value == null) {
            call.reject("value is required");
            return;
        }
        try {
            // commit(): the caller awaits this before relying on the value.
            boolean ok = prefs().edit().putString(key, encrypt(value)).commit();
            if (ok) {
                call.resolve();
            } else {
                call.reject("Secure store write failed");
            }
        } catch (Exception e) {
            call.reject("Secure store write failed", e);
        }
    }

    @PluginMethod
    public void remove(PluginCall call) {
        String key = key(call);
        if (key == null) {
            return;
        }
        prefs().edit().remove(key).commit();
        call.resolve();
    }
}

