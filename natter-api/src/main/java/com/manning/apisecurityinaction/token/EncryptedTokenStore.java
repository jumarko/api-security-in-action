package com.manning.apisecurityinaction.token;

import software.pando.crypto.nacl.SecretBox;
import spark.Request;

import java.security.Key;
import java.util.Optional;

/**
 * Token store implementation using encryption key to encrypt tokens via SecretBox.
 * Secret box provides _authenticated_ encryption so this implements {@link SecureTokenStore}.
 */
public class EncryptedTokenStore implements SecureTokenStore {

    private final TokenStore delegate;
    private final Key encryptionKey;

    public EncryptedTokenStore(TokenStore delegate, Key encryptionKey) {
        this.delegate = delegate;
        this.encryptionKey = encryptionKey;
    }

    @Override
    public String create(Request request, Token token) {
        var tokenId = this.delegate.create(request, token);
        // as per docs: A unique random nonce will be generated on each call
        return SecretBox.encrypt(this.encryptionKey, tokenId).toString();
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        var originalTokenId = decryptToken(tokenId);
        return delegate.read(request, originalTokenId);
    }

    @Override
    public void revoke(Request request, String tokenId) {
        var originalTokenId = decryptToken(tokenId);
        delegate.revoke(request, originalTokenId);
    }

    private String decryptToken(String encryptedTokenId) {
        return SecretBox.fromString(encryptedTokenId).decryptToString(this.encryptionKey);
    }
}
