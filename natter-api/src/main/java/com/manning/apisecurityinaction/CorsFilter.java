package com.manning.apisecurityinaction;

import spark.Filter;
import spark.Request;
import spark.Response;
import spark.Spark;

import java.util.Set;

/**
 * Intercepts all requests and make sure proper CORS headers are set.
 * This must happen before any authentication is checked,
 * because credentials are NOT sent on preflight requests.
 */
public class CorsFilter implements Filter {

    private final Set<String> allowedOrigins;

    public CorsFilter(Set<String> allowedOrigins) {
        this.allowedOrigins = Set.copyOf(allowedOrigins);
    }

    @Override
    public void handle(Request request, Response response) throws Exception {
        var origin = request.headers("Origin");
        if (origin != null && allowedOrigins.contains(origin)) {
            response.header("Access-Control-Allow-Origin", origin);
            // Update chapter 5: this is only needed for cookies
            // response.header("Access-Control-Allow-Credentials", "true");
            response.header("Vary", "origin");
        }

        if (isPreflightRequest(request)) {
            if (origin == null || !allowedOrigins.contains(origin)) {
                // CORS doesn't prescribe specific response codes but it's a good practice to use 403
                // in this situation
                Spark.halt(403);
            }

            // Update chapter 5: no need for whitelisting X-CSRF-Token anymore since we use tokens
            // response.header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token");
            response.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
            response.header("Access-Control-Allow-Methods", "GET, POST, DELETE");
            // Again, CORS doesn't prescribe a status code but it's common to return 204
            Spark.halt(204);
        }
    }

    private boolean isPreflightRequest(Request request) {
        return "OPTIONS".equals(request.requestMethod()) &&
                    request.headers().contains("Access-Control-Request-Method");
    }
}
