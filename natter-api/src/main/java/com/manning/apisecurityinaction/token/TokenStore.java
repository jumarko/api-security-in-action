package com.manning.apisecurityinaction.token;

import spark.Request;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Abstract interface for token storage operations.
 */
public interface TokenStore {

    String create(Request request, Token token);

    Optional<Token> read(Request request, String tokenId);

    void revoke(Request request, String tokenId);

    record Token(Instant expiry, String username, Map<String, String> attributes) {
        public Token(Instant expiry, String username) {
            this(expiry, username, new ConcurrentHashMap<>());
        }
    }

}
