package com.manning.apisecurityinaction.controllers;

import static spark.Spark.halt;

import com.manning.apisecurityinaction.token.TokenStore;
import org.json.JSONObject;
import spark.Request;
import spark.Response;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Implements a basic /sessions handler.
 * The client has to use HTTP Basic (later Bearer - chapter 5) authentication to access the endpoint.
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


    public void validateToken(Request request, Response response) {
        var tokenId = parseTokenId(request);
        if (tokenId == null) {
            return;
        }
        tokenStore.read(request, tokenId).ifPresent(token -> {
            if (Instant.now().isBefore(token.expiry())) {
                request.attribute("subject", token.username());
                token.attributes().forEach(request::attribute);
            } else {
                // we can again use standard WWW-Authenticate header
                // together with standard Bearer error codes
                response.header("WWW-Authenticate",
                        "Bearer error=\"invalid_token\", error_description=\"Expired\"");
                halt(401);
            }
        });
    }

    public JSONObject login(Request request, Response response) {
        String subject = request.attribute("subject");
        var expiry = Instant.now().plus(10, ChronoUnit.MINUTES);
        var token = new TokenStore.Token(expiry, subject);
        var tokenId = tokenStore.create(request, token);

        response.status(201);
        return new JSONObject().put("token", tokenId);
    }

    public JSONObject logout(Request request, Response response) {
        var tokenId = parseTokenId(request);
        if (tokenId == null) {
            throw new IllegalArgumentException("Missing token header");
        }
        tokenStore.revoke(request, tokenId);
        response.status(200);
        return new JSONObject();
    }

    private static String parseTokenId(Request request) {
        // note that in the book they named this `tokenId` too - that was confusing
        // and they had to mutate it below
        var authHeader = request.headers("Authorization");
        return (authHeader != null && authHeader.startsWith("Bearer ")) ? authHeader.substring(7) : null;
    }
}
