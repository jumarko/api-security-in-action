package com.manning.apisecurityinaction.token;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import spark.Request;

import java.sql.Date;
import java.text.ParseException;
import java.util.Optional;

public class SignedJwtTokenStore implements TokenStore {

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
            if (!jwt.verify(this.verifier)) {
                throw new JOSEException("Invalid signature");
            }
            var claims = jwt.getJWTClaimsSet();
            if (!claims.getAudience().contains(this.audience)) {
                throw new JOSEException("Incorrect audience");
            }

            var token = new Token(claims.getExpirationTime().toInstant(), claims.getSubject());
            var attrs = claims.getJSONObjectClaim("attrs");
            attrs.forEach((k,v) -> token.attributes().put(k, (String) v));
            return Optional.of(token);
        } catch (ParseException | JOSEException e) {
            return Optional.empty();
        }
    }

    @Override
    public void revoke(Request request, String tokenId) {

    }
}
