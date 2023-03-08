package com.manning.apisecurityinaction.token;

/**
 * Confidential token store only guarantees that information is kept confidential,
 * but it doesn't guarantee integrity or authenticity.
 */
public interface ConfidentialTokenStore extends TokenStore {
}
