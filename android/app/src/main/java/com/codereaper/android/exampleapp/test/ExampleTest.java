package com.codereaper.android.exampleapp.test;

import android.content.Context;
import android.test.InstrumentationTestCase;

import com.codereaper.android.util.PEMKey;
import com.codereaper.android.util.Payload;

import org.json.JSONObject;

import java.security.PrivateKey;
import java.security.PublicKey;

public class ExampleTest extends InstrumentationTestCase {
    public void testSealingAndUnsealing() throws Exception {
        JSONObject json = new JSONObject();
        json.put("data", "makes life worth living");

        Context context = getInstrumentation().getTargetContext().getApplicationContext();

        PrivateKey privateKey = PEMKey.getPrivateKey("private_key", context);
        PublicKey publicKey = PEMKey.getPublicKey("public_key", context);

        JSONObject sealed = Payload.seal(json, publicKey);
        JSONObject recreatedJson = Payload.open(sealed, privateKey);

        assertEquals(json.get("data"), recreatedJson.get("data"));
    }

    public void testUnsealing() throws Exception {
        JSONObject sealed = new JSONObject();
        sealed.put("payload", "C8Qz+5ogNcP/yFGIZRjZvk44qHxu1U0duQSrSdqPdnfhIjs=");
        sealed.put("token", "GpbIl2xnpntTbPsvdJWyJBhwWAvbkifCkz++UIAys8URlE2UAUXJH0AP6IrfI0Xh1OB6F9TTQPaNp0K2ewZL7fbe1FqZ8KA94FNgwwc5eQtVFBRwkdlkKVUr0UnaEkG5DaeFmpeR/vVX2RYQyLpd970HnMLCDpCAE/gUD9YUmhJ737dyWOdnAlAzIcDMiYXbFXUq8hIQbYPorxlvBUDcIboC2d1sypR/VOcCLeia7PfhM/vWYXlzKzKjQcixHIn/tK7pWFBkbGMxZd2fH6P5u3ZSrPy3b1T3b11a+K26ED8wUihmmxnjAUfdioWT57zoGm+PZbRDzslQacv73uSnrQ==");

        Context context = getInstrumentation().getTargetContext().getApplicationContext();
        PrivateKey privateKey = PEMKey.getPrivateKey("private_key", context);

        JSONObject recreatedJson = Payload.open(sealed, privateKey);

        assertEquals("makes life worth living", recreatedJson.get("data"));
    }
}
