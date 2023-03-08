package com.manning.apisecurityinaction.token;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import spark.Request;

import java.sql.Date;
import java.text.ParseException;
import java.util.Optional;
import java.util.Set;

/**
 * TokenStore implementation using Signed JWT tokens stored on the client.
 * It doesn't provide confidentiality out of the box thus it only implements {@link AuthenticatedTokenStore}.
 */
public class SignedJwtTokenStore implements AuthenticatedTokenStore {

    private final JWSSigner signer;
    private final JWSVerifier verifier;
    private final JWSAlgorithm algorithm;
    private final String audience;
    private final JWSHeader header;

    public SignedJwtTokenStore(JWSSigner signer, JWSVerifier verifier, JWSAlgorithm algorithm, String audience) {
        this.signer = signer;
        this.verifier = verifier;
        this.audience = audience;
        this.algorithm = algorithm;
        // I have this here instead of both create and read methods because it's immutable and only depends on algorithm
        this.header = new JWSHeader(algorithm);
    }

    @Override
    public String create(Request request, Token token) {
        var claimsSet = new JWTClaimsSet.Builder()
                .subject(token.username())
                .audience(this.audience)
                .expirationTime(Date.from(token.expiry()))
                .claim("attrs", token.attributes())
                .build();
        var jwt = new SignedJWT(this.header, claimsSet);
        try {
            jwt.sign(this.signer);
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        try {
            // first parse the Compact Serialization Format
            var jwt = SignedJWT.parse(tokenId);

            // verify JWT's signature
            if (!jwt.verify(this.verifier)) {
                throw new JOSEException("Invalid signature");
            }

            // check audience
            var claims = jwt.getJWTClaimsSet();
            if (!claims.getAudience().contains(this.audience)) {
                throw new JOSEException("Incorrect audience");
            }

            // check expiration time - NOTE: this isn't in the book!
            // Notice that this also checks audience
            // See https://www.javadoc.io/doc/com.nimbusds/nimbus-jose-jwt/latest/com/nimbusds/jwt/proc/DefaultJWTClaimsVerifier.html
            var claimsVerifier = new DefaultJWTClaimsVerifier<>(this.audience, null, Set.of("exp"));
            claimsVerifier.verify(claims, null);

            var token = new Token(claims.getExpirationTime().toInstant(), claims.getSubject());
            var attrs = claims.getJSONObjectClaim("attrs");
            attrs.forEach((k,v) -> token.attributes().put(k, (String) v));
            return Optional.of(token);
        } catch (ParseException | JOSEException | BadJWTException e) {
            return Optional.empty();
        }
    }

    @Override
    public void revoke(Request request, String tokenId) {

    }
}
