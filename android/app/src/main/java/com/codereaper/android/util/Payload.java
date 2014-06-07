package com.codereaper.android.util;

import android.util.Base64;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Payload {

    /**
     * Creates a sealed JSONObject
     * <p>
     * Creates a sealed JSONObject in the same way as
     * openssl_seal(...) does for PHP. The sealed object
     * have two keys, payload and token. Payload is the
     * data and the token is the envelop key.
     * <p>
     *
     * @param  json Object to seal
     * @param  PublicKey key
     * @return the sealed object.
     */
    static public JSONObject seal(JSONObject json, PublicKey key) {
        JSONObject encrypted = null;

        try {
            encrypted = encrypt(json, key);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return encrypted;
    }

    /**
     * Returns an unsealed JSONObject
     * <p>
     * Return an unsealed JSONObject in the same way as
     * openssl_sign(...) does for PHP.
     * <p>
     *
     * @param  sealed Object to unseal
     * @param  PrivateKey key
     * @return the unsealed object.
     */
    static public JSONObject open(JSONObject sealed, PrivateKey key) {
        JSONObject json = null;

        try {
            json = decrypt(sealed, key);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return json;
    }

    static private JSONObject decrypt(JSONObject json, PrivateKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, JSONException, UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        String envelope = json.getString("token");

        final Cipher cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipherRSA.init(Cipher.DECRYPT_MODE, key);
        byte[] envelopeKey = cipherRSA.doFinal(Base64.decode(envelope.getBytes("UTF-8"), Base64.DEFAULT));

        String payload = json.getString("payload");
        SecretKey secretKey = new SecretKeySpec(envelopeKey, "RC4");
        final Cipher cipherRC4 = Cipher.getInstance("RC4");
        cipherRC4.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedPayload = cipherRC4.doFinal(Base64.decode(payload.getBytes("UTF-8"), Base64.DEFAULT));

        String jsonString = new String(decryptedPayload, "UTF-8");
        return new JSONObject(jsonString);
    }

    static private JSONObject encrypt(JSONObject json, final PublicKey key) throws JSONException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, NoSuchProviderException {
        KeyGenerator keyGen = KeyGenerator.getInstance("RC4");
        keyGen.init(128); // http://www.php.net/manual/en/function.openssl-seal.php#53856
        SecretKey envelopeKey = keyGen.generateKey();

        final Cipher cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipherRSA.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedEnvelopeKey = cipherRSA.doFinal(envelopeKey.getEncoded());

        final Cipher cipherRC4 = Cipher.getInstance("RC4");
        cipherRC4.init(Cipher.ENCRYPT_MODE, envelopeKey);
        byte[] encrypted = cipherRC4.doFinal(json.toString().getBytes("UTF-8"));

        JSONObject encryptedPayload = new JSONObject();
        encryptedPayload.put("payload", Base64.encodeToString(encrypted, Base64.DEFAULT));
        encryptedPayload.put("token", Base64.encodeToString(encryptedEnvelopeKey, Base64.DEFAULT));

        return encryptedPayload;
    }
}