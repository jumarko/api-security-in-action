package com.manning.apisecurityinaction.token;

import spark.Request;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.util.Optional;

import javax.crypto.Mac;

/**
 * HmacTokenStore is a delegating TokenStore implementation
 * which turns any token store into an _authenticated_ token store.
 *
 * If the delegate is already confidential, then the result is SecureTokenStore,
 * otherwise it's AuthenticatedTokenStore.
 * That's why the constructor is private and we offer two factory methods instead.
 * The class itself must implement SecureTokenStore otherwise the types wouldn't match.
 */
public class HmacTokenStore implements SecureTokenStore {

    private final TokenStore delegate;
    private final Key macKey;

    public static SecureTokenStore wrap(ConfidentialTokenStore store, Key macKey) {
        return new HmacTokenStore(store, macKey);
    }

    public static AuthenticatedTokenStore wrap(AuthenticatedTokenStore store, Key macKey) {
        return new HmacTokenStore(store, macKey);
    }

    private HmacTokenStore(TokenStore delegate, Key macKey) {
        this.delegate = delegate;
        this.macKey = macKey;
    }

    @Override
    public String create(Request request, Token token) {
        var tokenId = delegate.create(request, token);
        var tag = hmac(tokenId);
        return tokenId + "." + Base64Url.encode(tag);
    }

    private byte[] hmac(String tokenId) {
        try {
            var mac = Mac.getInstance(macKey.getAlgorithm());
            mac.init(macKey);
            return mac.doFinal(tokenId.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        // validate the token first, then read it from the delegate if it's valid
        // this helps to prevent timing attacks
        var index = tokenId.lastIndexOf('.');
        if (index == -1) { return Optional.empty(); }
        var realTokenId = tokenId.substring(0, index);
        var providedTag = Base64Url.decode(tokenId.substring( index + 1));
        var computedTag = hmac(realTokenId);
        // check if the tag is valid - notice the constant-time equality check using MessageDigest#isEqual
        if (!MessageDigest.isEqual(providedTag, computedTag)) {
            return Optional.empty();
        }
        return delegate.read(request, realTokenId);
    }

    @Override
    public void revoke(Request request, String tokenId) {
        delegate.revoke(request, tokenId);
    }
}
