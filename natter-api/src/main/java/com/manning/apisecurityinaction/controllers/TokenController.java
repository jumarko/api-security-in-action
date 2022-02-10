package com.manning.apisecurityinaction.controllers;

import com.manning.apisecurityinaction.token.TokenStore;
import org.json.JSONObject;
import spark.Request;
import spark.Response;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Implements a basic /sessions handler.
 * The client has to use HTTP Basic authentication to access the endpoint.
 * If authentication is OK, we issue a time-limited token
 * which can then be used for all subsequent requests.
 *
 * "Logging" is treated as creating a new session resource: therefore we use the /sessions endpoint,
 * not a /login endpoint.
 *
 * The basic auth is taken care of by UserController
 * and putting TokenController after the existing authenticadtion filters.
 */
public class TokenController {

    private final TokenStore tokenStore;

    public TokenController(TokenStore tokenStore) {
        this.tokenStore = tokenStore;
    }

    public JSONObject login(Request request, Response response) {
        String subject = request.attribute("subject");
        var expiry = Instant.now().plus(10, ChronoUnit.MINUTES);
        var token = new TokenStore.Token(expiry, subject);
        var tokenId = tokenStore.create(request, token);

        response.status(201);
        return new JSONObject().put("token", tokenId);
    }
    
    public void validateToken(Request request, Response response) {
        // WARNING: CSRF attack possible!
        var tokenId = request.headers("X-CSRF-Token");
        if (tokenId == null) return;
        tokenStore.read(request, tokenId).ifPresent(token -> {
            if (Instant.now().isBefore(token.expiry())) {
                request.attribute("subject", token.username());
                token.attributes().forEach(request::attribute);
            }
        });
    }
}
