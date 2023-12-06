package com.manning.apisecurityinaction.controllers;

import static java.time.Instant.now;

import com.manning.apisecurityinaction.token.SecureTokenStore;
import com.manning.apisecurityinaction.token.TokenStore;
import spark.Request;
import spark.Response;

import java.net.URI;
import java.time.Duration;
import java.util.Objects;

/**
 * Capability-based access control (chapter 9).
 * This controller creates a capability-URI by reusing an existing TokenStore implementation
 * (you can use any secure TokenStore impl. - in this chapter, we'll use DatabaseTokenStore)
 * to create a token encoding two specific attributes, that is 'path' and 'perms' (permissions).
 * The token is stored in the standard 'access_token' query parameter (see RFC 6750).
 */
public class CapabilityController {
    private final SecureTokenStore tokenStore;

    public CapabilityController(SecureTokenStore tokenStore) {
        this.tokenStore = tokenStore;
    }

    public URI createURI(Request request, String path, String perms, Duration expiryDuration) {
         // NOTE: username is null because capability URIs don't have any associated username (they can be shared)
        var token = new TokenStore.Token(now().plus(expiryDuration), null);
        token.attributes().put("path", path);
        token.attributes().put("perms", perms);
        final String tokenId = tokenStore.create(request, token);
        var uri = URI.create(request.uri());
        return uri.resolve(path + "?access_token=" + tokenId);
    }

    public void lookupPermissions(Request request, Response response) {
        var tokenId = request.queryParams("access_token");
        // no token means no access granted
        if (tokenId == null) { return; }

        tokenStore.read(request, tokenId).ifPresent(token -> {
            var tokenPath = token.attributes().get("path");
            if (Objects.equals(tokenPath, request.pathInfo())) {
                // if paths match the token is for this resource - we can set request permissions to the perms encoded in the token
                request.attribute("perms", token.attributes().get("perms"));
            }
        });
    }
}
