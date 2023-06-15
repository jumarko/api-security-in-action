package com.manning.apisecurityinaction.token;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Encapsulates the logic for revoking OAuth2 tokens.
 * See https://www.rfc-editor.org/rfc/rfc7009.
 *
 * High-level, the token is revoked by calling a dedicated AS endpoint,
 * while passing client credentials as authentication mechanism
 * and the token in the POST body.
 * The tokens can only be removed by the client that they were issued to.
 *
 * This serves mostly as an example of such implementation.
 * It's not in direct use in the application and it uses hardcoded endpoint.
 */
public class TokenRevocation {

    private static final URI revocationEndpoint = URI.create("https://as.example.com:8443/oauth2/token/revoke");

    public static void main(String[] args) throws IOException, InterruptedException {
        if (args.length != 3) {
            throw new IllegalArgumentException("RevokeAccessToken clientId clientSecret token");
        }

        var clientId = args[0];
        var clientSecret = args[1];
        var token = args[2];

        var credentials = URLEncoder.encode(clientId, UTF_8) + ":" + URLEncoder.encode(clientSecret, UTF_8);
        var authorization = "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(UTF_8));
        var httpClient = HttpClient.newHttpClient();
        var form = "token=" + URLEncoder.encode(token, UTF_8) + "&token_type_hint=access_token";
        var httpRequest = HttpRequest.newBuilder()
                .uri(revocationEndpoint)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Authorization", authorization)
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build();
        httpClient.send(httpRequest, HttpResponse.BodyHandlers.discarding());

    }
}
