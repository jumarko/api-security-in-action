package com.manning.apisecurityinaction;

import com.google.common.util.concurrent.RateLimiter;
import org.dalesbred.result.EmptyResultException;
import org.json.JSONException;
import org.json.JSONObject;
import spark.Request;
import spark.Response;
import spark.Spark;

import com.manning.apisecurityinaction.controllers.SpaceController;
import org.dalesbred.Database;

/**
 * The main entry point that sets up the routes
 * Notice that in the book this is all in the Main class.
 */
public class WebApp {
    private final Database database;

    public WebApp(Database database) {
        this.database = database;
    }

    private void setupRateLimiting(int maxRequestsPerSecond) {
        var rateLimiter = RateLimiter.create(maxRequestsPerSecond);
        Spark.before(((request, response) -> {
            if (!rateLimiter.tryAcquire()) {
                response.header("Retry-After", "2");
                // this throws an exception so no further statements are executed in the init method
                Spark.halt(429);
            }
        }));
    }

    public void init() {
        var spaceController = new SpaceController(database);

        setupRateLimiting(2);

        Spark.post("/spaces", spaceController::createSpace);

        // In the book they first use after() but it should be afterAfter()
        // otherwise you'll get text/html content type for error responses
        // -> see page 37 about Content-Type
        // This commit fixes it anyway: https://github.com/NeilMadden/apisecurityinaction/commit/067b05a72fe8ed92b09d545912e8a33f8a909ab5#diff-eae019c32d4ba4dda402c532030540ae66b80cc7f7687fe353766126427d5814
        Spark.afterAfter((request, response) -> response.type("application/json"));

        Spark.internalServerError(new JSONObject()
                .put("error", "internal server error").toString());
        Spark.notFound(new JSONObject("error", "not found").toString());

        Spark.exception(IllegalArgumentException.class, WebApp::badRequest);
        Spark.exception(JSONException.class, WebApp::badRequest);
        Spark.exception(EmptyResultException.class, (e, request, response) -> response.status(404));

        // don't leak internal server info
        Spark.afterAfter((request, response) -> response.header("Server", ""));

        // SECURITY HEADERS
        Spark.afterAfter(((request, response) -> {
            response.header("X-Content-Type-Options", "no-sniff");
            response.header("X-Frame-Options", "DENY");
            // disable XSS protection since it has some vulnerabilities on its own
            response.header("X-XSS-Protection", "0");
            response.header("Cache-Control", "no-store");
            response.header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox");
        }));
    }

    private static <T extends Exception> void badRequest(Exception e, Request request, Response response) {
        response.status(400);
        response.body(String.format("{\"error\": \"%s\"}", e.getMessage()));
    }
}
