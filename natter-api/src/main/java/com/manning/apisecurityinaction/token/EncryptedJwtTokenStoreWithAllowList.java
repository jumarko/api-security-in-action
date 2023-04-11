package com.manning.apisecurityinaction.token;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import spark.Request;

import java.text.ParseException;
import java.util.Date;
import java.util.Optional;
import java.util.Set;

import javax.crypto.SecretKey;

/**
 * Token store implementation using encrypted JWT tokens stored on the client
 * and DatabaseTokenStore as an allow list to implement "hybrid tokens".
 * This is a small modification of {@link EncryptedJwtTokenStore} to keep them separate.
 */
public class EncryptedJwtTokenStoreWithAllowList implements SecureTokenStore {

    // expected JWT audience
    private static final String AUD = "https://localhost:4567";

    private final SecretKey encKey;
    private final DatabaseTokenStore tokenAllowList;

    public EncryptedJwtTokenStoreWithAllowList(SecretKey encKey, DatabaseTokenStore tokenAllowList) {
        this.encKey = encKey;
        // NEW: tokenAllowlist is the db store
        this.tokenAllowList = tokenAllowList;
    }

    @Override
    public String create(Request request, Token token) {

        // NEW: create a db token
        // - we remove all the other attributes (by creating a copy of the token) to save space in the DB table
        var allowlistToken = new Token(token.expiry(), token.username());
        var jwtId = tokenAllowList.create(request, allowlistToken);

        // use JWTClaimsSet to build the claims
        var claimsBuilder = new JWTClaimsSet.Builder()
                .jwtID(jwtId) // NEW
                .subject(token.username())
                .audience(AUD)
                .expirationTime(Date.from(token.expiry()));
        token.attributes().forEach(claimsBuilder::claim);

        // create JWEHeader
        var header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256);

        // create the encrypted JWT
        var jwt = new EncryptedJWT(header, claimsBuilder.build());
        try {
            var encrypter = new DirectEncrypter(this.encKey);
            jwt.encrypt(encrypter);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
        return jwt.serialize();
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        try {
            // parse and decrypt the jwt
            var jwt = EncryptedJWT.parse(tokenId);
            var decryptor = new DirectDecrypter(this.encKey);
            jwt.decrypt(decryptor);

            // get and verify claims
            var claims = jwt.getJWTClaimsSet();

            // NEW: check if the token is in the db
            if (tokenAllowList.read(request, claims.getJWTID()).isEmpty()) {
                return Optional.empty();
            }

            if (!claims.getAudience().contains(AUD)) {
                // do not reveal the exact failure to the end user / attacker
                return Optional.empty();
            }
            var token = new Token(claims.getExpirationTime().toInstant(), claims.getSubject());
            var ignore = Set.of("exp", "sub", "aud");
            for (String attr : claims.getClaims().keySet()) {
                if (ignore.contains(attr)) {
                    continue;
                }
                token.attributes().put(attr, claims.getStringClaim(attr));
            }
            return Optional.of(token);
        } catch (ParseException | JOSEException e) {
           // do not reveal the exact failure to the end user / attacker
            return Optional.empty();
        }
    }

    @Override
    public void revoke(Request request, String tokenId) {
        // NEW: whole this content is new but the important thing is deleting from the DB
        try {
            var jwt = EncryptedJWT.parse(tokenId);
            var decryptor = new DirectDecrypter(this.encKey);
            jwt.decrypt(decryptor);

            // get and verify claims
            var claims = jwt.getJWTClaimsSet();

            // NEW: to revoke, simply delete the token from the DB
            tokenAllowList.revoke(request, claims.getJWTID());
        } catch (ParseException | JOSEException e) {
            throw new IllegalArgumentException("Invalid token", e);
        }
    }
}
