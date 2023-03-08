package com.manning.apisecurityinaction.token;

/**
 * Secure token store ensures confidentiality, integrity, and authenticity.
 */
public interface SecureTokenStore extends AuthenticatedTokenStore, ConfidentialTokenStore {
}
