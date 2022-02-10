package com.manning.apisecurityinaction.token;

import spark.Request;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;

/**
 * Simple implementation of TokenStore storing token attributes in session cookies.
 */
public class CookieTokenStore implements TokenStore {

    @Override
    public String create(Request request, Token token) {
        // To avoid session fixation attacks, we first check if the session is already present
        // and invalidate it if it exists
        var session = request.session(false);
        if (session != null) {
            session.invalidate();
        }
        // ... then create a completely new session
        session = request.session(true);

        // store token attributes in session's attributes
        session.attribute("username", token.username());
        session.attribute("expiry", token.expiry());
        session.attribute("attrs", token.attributes());
        // return unique session identifier
        return Base64Url.encode(sha256(session.id()));
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        var session = request.session(false); // pass false to check if valid session is present
        if (session == null) {
            return Optional.empty();
        } else {
            // the provided token is expected to be Base64-encoded version of SHA256 of session token
            var providedToken = Base64Url.decode(tokenId);
            var computedToken =  sha256(session.id());
            if (!MessageDigest.isEqual(providedToken, computedToken)) {
                // somebody is trying to forge the token?
                return Optional.empty();
            }

            var token = new TokenStore.Token(session.attribute("expiry"), session.attribute("username"));
            token.attributes().putAll(session.attribute("attrs"));
            return Optional.of(token);
        }
    }

    static byte[] sha256(String tokenId) {
        try {
            var sha256 = MessageDigest.getInstance("sha256");
            return sha256.digest(tokenId.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Expected SHA-256 algorithm not supported", e);
        }
    }
}
