package com.codereaper.android.util;

import android.content.Context;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


public class PEMKey {

    /**
     * Read a public key
     * <p>
     * Read a public key in DER form from the raw sources.
     * <p>
     *
     * @param  String Name of the file
     * @param  context Current context
     * @return PublicKey
     */
    static public PublicKey getPublicKey(String name, Context context) {
    	PublicKey key = null;

        try {
            key = publicKey(name, context);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return key;
    }

    /**
     * Read a private key
     * <p>
     * Read a private key in DER form from the raw sources.
     * <p>
     *
     * @param  String Name of the file
     * @param  context Current context
     * @return PrivateKey
     */
    static public PrivateKey getPrivateKey(String name, Context context) {
        PrivateKey key = null;

        try {
            key = privateKey(name, context);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return key;
    }

    static private PublicKey publicKey(String name, Context context) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = bytesKey(name, context);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");

        PublicKey publicKey = kf.generatePublic(spec);
        return publicKey;
    }

    static private PrivateKey privateKey(String name, Context context) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = bytesKey(name, context);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");

        PrivateKey privateKey = kf.generatePrivate(spec);
        return privateKey;
    }

    static private byte[] bytesKey(String name, Context context) throws IOException {
        InputStream fis = context.getResources().openRawResource(context.getResources().getIdentifier(name, "raw", context.getPackageName()));
        DataInputStream dis = new DataInputStream(fis);

        byte[] keyBytes = new byte[fis.available()];
        dis.readFully(keyBytes);

        dis.close();

        return keyBytes;
    }
}