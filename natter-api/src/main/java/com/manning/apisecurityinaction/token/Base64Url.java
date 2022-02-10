package com.manning.apisecurityinaction.token;

import java.nio.charset.Charset;
import java.util.Base64;

public class Base64Url {

    // For more about padding and when it's needed see: https://stackoverflow.com/questions/4080988/why-does-base64-encoding-require-padding-if-the-input-length-is-not-divisible-by
    private static final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder decoder = Base64.getUrlDecoder();

    public static String encode(byte[] data) {
        // Note that this uses ISO-8859-1 - should be safe since Base64 uses only ASCII characters anyway
        return encoder.encodeToString(data);
    }

    public static byte[] decode(String encoded) {
        return decoder.decode(encoded);
    }

    public static void main(String[] args) {
        System.out.println("Default charset: " + Charset.defaultCharset());
        System.out.println(encode("ahojľščáýíô".getBytes()));
        System.out.println("decoded: " + new String(decode(encode("ahojľščáýíô".getBytes()))));
    }
}
