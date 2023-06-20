package com.manning.apisecurityinaction.token;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import spark.Request;

import java.net.MalformedURLException;
import java.net.URI;
import java.text.ParseException;
import java.util.Optional;

/**
 * Section 7.4.4 JWT-based Access tokens.
 *
 * The public key for verification is retrieved from `jwkSetUri`.
 * The key is then used to validate the signature of the token (see the `read` method).
 * In that process, `signatureAlgorithm` is used.
 *
 * Separately, we verify the issuer and the audience - this is important to prevent certain types of attacks (see Ch6).
 *
 * Finally, we parse token scopes - depending on the AS implementation, we support either single string in the "scope" field,
 * or a list of strings.
 */
public class SignedJwtAccessTokenStore implements SecureTokenStore {

    private final String expectedIssuer;
    private final String expectedAudience;
    private final JWSAlgorithm signatureAlgorithm;
    private final JWKSource<SecurityContext> jwkSource;

    public SignedJwtAccessTokenStore(String expectedIssuer, String expectedAudience, JWSAlgorithm signatureAlgorithm, URI jwkSetUri) throws MalformedURLException {
        this.expectedIssuer = expectedIssuer;
        this.expectedAudience = expectedAudience;
        this.signatureAlgorithm = signatureAlgorithm;
        this.jwkSource = JWKSourceBuilder.create(jwkSetUri.toURL()).build();
    }

    @Override
    public String create(Request request, Token token) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void revoke(Request request, String tokenId) {
        throw new UnsupportedOperationException();
    }


    @Override
    public Optional<Token> read(Request request, String tokenId) {
        try {
            var verifier = new DefaultJWTProcessor<>();
            var keySelector = new JWSVerificationKeySelector<>(signatureAlgorithm, jwkSource);
            verifier.setJWSKeySelector(keySelector);
            // verify the signature and the expiry time, returns claims
            var claims = verifier.process(tokenId, null);

            // our turn - verifier issuer and the audience
            if (!expectedIssuer.equals(claims.getIssuer())) {
                return Optional.empty();
            }
            if (!claims.getAudience().contains(expectedAudience)) {
                return Optional.empty();
            }

            // create the Token with given expiry and subjet
            var token = new Token(claims.getExpirationTime().toInstant(), claims.getSubject());

            // Assemble scopes
            // First try to parse "scope" as a string, then fallback to an array of strings
            String scope;
            try {
                scope = claims.getStringClaim("scope");
            } catch (ParseException e) {
                scope = String.join(" ", claims.getStringListClaim("scope"));
            }
            token.attributes().put("scope", scope);
            return Optional.of(token);

        } catch (ParseException | BadJOSEException | JOSEException e) {
            return Optional.empty();
        }

    }

}
