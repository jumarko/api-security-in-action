package com.manning.apisecurityinaction.token;

import static java.nio.charset.StandardCharsets.UTF_8;

import org.json.JSONObject;
import spark.Request;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

/**
 * This is a TokenStore implementation that uses OAuth2 Token Introspection Endpoint
 * to validate access tokens.
 */
public class OAuth2TokenStore implements SecureTokenStore {

    private final URI introspectionEndpoint;
    private final String authorization;
    private final HttpClient httpClient;

    public OAuth2TokenStore(URI introspectionEndpoint, String clientId, String clientSecret) {
        this.introspectionEndpoint = introspectionEndpoint;

        var credentials = URLEncoder.encode(clientId, UTF_8) + ":" + URLEncoder.encode(clientSecret, UTF_8);
        this.authorization = "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(UTF_8));

        this.httpClient = HttpClient.newHttpClient();
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        // Notice we validate the token format to adhere to the "always validate all inputs" principle (chapter 2, p.50)
        if (!tokenId.matches("[\\x20-\\x7E]{1,1024}")) {
            return Optional.empty();
        }

        // Another principle: properly encoded parameters
        var form = "token=" + URLEncoder.encode(tokenId, UTF_8) + "&token_type_hint=access_token";
        var httpRequest = HttpRequest.newBuilder()
                .uri(introspectionEndpoint)
                .header("Content-Type", "application/x-www-form-urlencoded")
                // use client credentials to authenticate against introspection endpoint
                .header("Authorization", authorization)
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build();

        try {
            var httpResponse = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
            if (httpResponse.statusCode() == 200) {
                var json = new JSONObject(httpResponse.body());
                if (json.getBoolean("active")) {
                    return processResponse(json);
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }
        return Optional.empty();
    }

    private Optional<Token> processResponse(JSONObject introspectionResponse) {
        var expiry = Instant.ofEpochSecond(introspectionResponse.getLong("exp"));
        var subject = introspectionResponse.getString("sub");
        var token = new Token(expiry, subject);
        token.attributes().put("scope", introspectionResponse.getString("scope"));
        token.attributes().put("client_id", introspectionResponse.optString("client_id"));
        return Optional.of(token);
    }


    /*
       By throwing exception in #create and #revoke methods
       we effectively disable login and logout
       and force clients to obtain access tokens from AS.
     */

    @Override
    public String create(Request request, Token token) {
        throw new UnsupportedOperationException("Obtain access token from AS!");
    }


    @Override
    public void revoke(Request request, String tokenId) {
        throw new UnsupportedOperationException("Obtain access token from AS!");
    }
}
