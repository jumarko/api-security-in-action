package com.manning.apisecurityinaction.token;

import spark.Request;

import java.util.Optional;

/**
 * Simple implementation of TokenStore storing token attributes in session cookies.
 */
public class CookieTokenStore implements TokenStore {

    @Override
    public String create(Request request, Token token) {
        // WARNING: session fixation vulnerability
        var session = request.session(true);
        // store token attributes in session's attributes
        session.attribute("username", token.username());
        session.attribute("expiry", token.expiry());
        session.attribute("attrs", token.attributes());
        // return unique session identifier
        return session.id();
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        var session = request.session(false); // pass false to check if valid session is present
        if (session == null) {
            return Optional.empty();
        } else {
            var token = new TokenStore.Token(session.attribute("expiry"), session.attribute("username"));
            token.attributes().putAll(session.attribute("attrs"));
            return Optional.of(token);
        }
    }
}
