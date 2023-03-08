package com.manning.apisecurityinaction.token;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.KeyLengthException;
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
 * Token store implementation using encrypted JWT tokens stored on the client.
 * Normal JWTs are authenticated + encryption => SecureTokenStore.
 */
public class EncryptedJwtTokenStore implements SecureTokenStore {

    // expected JWT audience
    private static final String AUD = "https://localhost:4567";

    private final SecretKey encKey;

    public EncryptedJwtTokenStore(SecretKey encKey) {
        this.encKey = encKey;
    }

    @Override
    public String create(Request request, Token token) {
        // use JWTClaimsSet to build the claims
        var claimsBuilder = new JWTClaimsSet.Builder()
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
        // TODO: blank for now (see section 6.6)
    }
}
