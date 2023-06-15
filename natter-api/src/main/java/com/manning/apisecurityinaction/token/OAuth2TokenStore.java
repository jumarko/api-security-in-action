package com.manning.apisecurityinaction.token;

import static java.nio.charset.StandardCharsets.UTF_8;

import org.json.JSONObject;
import spark.Request;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

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

        this.httpClient = HttpClient.newBuilder()
                // use more secure SSL settings (ciphers, etc.)
                .sslParameters(initSslParams())
                // trust only AS ca certificate - I DO NOT USE THIS
                // .sslContext(initTrustStore())
                .build();
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


    /**
     * See Mozilla's "Intermediate" recommendations: https://wiki.mozilla.org/Security/Server_Side_TLS
     */
    private SSLParameters initSslParams() {
        var sslParams = new SSLParameters();
        // you can drop TLSv1.2 if all clients support TLSv1.3
        sslParams.setProtocols(new String[] {"TLSv1.3", "TLSv1.2"});
        sslParams.setCipherSuites(new String[] {
                // TLS 1.3 ciphers
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
                // TLS 1.2 ciphers - those starting with TLS_ECDHE offer "forward secrecy"
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        });
        sslParams.setUseCipherSuitesOrder(true);
        sslParams.setEndpointIdentificationAlgorithm("HTTPS");
        return sslParams;
    }

    /**
     * Creates a keystore containing AS' root ca certificate
     * I'm not using this, just adding it for completeness
     */
    private SSLContext initTrustStore() {
        try {
            var trustedCerts = KeyStore.getInstance("PKCS12");
            trustedCerts.load(new FileInputStream("as.example.com.ca.p12"), "changeit".toCharArray());
            var tmf = TrustManagerFactory.getInstance("PKIX");
            tmf.init(trustedCerts);
            var sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);
            return sslContext;
        } catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException(e);
        }
    }
}
