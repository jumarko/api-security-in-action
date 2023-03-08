package com.manning.apisecurityinaction.token;

/**
 * Authenticated token store ensures authenticity / integrity but doesn't guarantee confidentiality.
 */
public interface AuthenticatedTokenStore extends TokenStore {
}
