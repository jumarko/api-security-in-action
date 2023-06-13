package com.manning.apisecurityinaction.oauth;

import java.nio.charset.StandardCharsets;

public class Utils {

    String addPkceChallengeCode(spark.Request request, String authorizeRequest) throws Exception {
        var secureRandom = new java.security.SecureRandom();
        var encoder = java.util.Base64.getUrlEncoder().withoutPadding();

        // generate the code verifier
        var verifierBytes = new byte[32];
        secureRandom.nextBytes(verifierBytes);
        var verifier = encoder.encodeToString(verifierBytes);

        // store it in the session
        request.session(true).attribute("verifier", verifier);

        // generate SHA256 of the code verifier and add it as a request param to the redirect url
        var sha256 = java.security.MessageDigest.getInstance("SHA-256");
        var challenge = encoder.encodeToString(sha256.digest(verifier.getBytes(StandardCharsets.UTF_8)));
        return authorizeRequest + "&code_challenge=" + challenge + "&code_challenge_method=S256";
    }
}
