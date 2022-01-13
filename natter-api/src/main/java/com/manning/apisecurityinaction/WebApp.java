package com.manning.apisecurityinaction;

import com.google.common.util.concurrent.RateLimiter;
import com.manning.apisecurityinaction.controllers.AuditController;
import com.manning.apisecurityinaction.controllers.ModeratorController;
import com.manning.apisecurityinaction.controllers.UserController;
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

        // server the development site over HTTPS
        // - the certificate was generated via mkcert tool: https://github.com/FiloSottile/mkcert
        //       mkcert -pkcs12 localhost
        Spark.secure("localhost.p12", "changeit", null, null);

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
        setupRateLimiting(5);

        var spaceController = new SpaceController(database);

        var userController = new UserController(database);

        // authentication
        Spark.before(userController::authenticate);

        var auditController = new AuditController(database);
        Spark.before((auditController::auditRequestStart));
        Spark.afterAfter((auditController::auditRequestEnd));
        Spark.get("/logs", auditController::readAuditLog);



        // require authentication for all /spaces requests          
        Spark.before("/spaces", userController::requireAuthentication);
        Spark.post("/spaces", spaceController::createSpace);
        // only users with write permission can post messages
        Spark.before("/spaces/:spaceId/messages", userController.requirePermissions("POST", "w"));
        Spark.post("/spaces/:spaceId/messages", spaceController::postMessage);

        // only users with read permissions can read messages
        Spark.before("/spaces/:spaceId/messages", userController.requirePermissions("GET", "r"));
        Spark.get("/spaces/:spaceId/messages/:msgId", spaceController::readMessage);
        Spark.before("/spaces/:spaceId/messages/*", userController.requirePermissions("GET", "r"));
        Spark.get("/spaces/:spaceId/messages", spaceController::findMessages);

        var moderatorController = new ModeratorController(database);
        Spark.before("/spaces/:spaceId/messages/:msgId", userController.requirePermissions("DELETE", "d"));
        Spark.delete("/spaces/:spaceId/messages/:msgId", moderatorController::deletePost);

        Spark.post("/users", userController::registerUser);

        // WARNING: possible privilege escalation attack
        Spark.before("/spaces/:spaceId/members", userController.requirePermissions("POST", "r"));
        Spark.post("/spaces/:spaceId/members", spaceController::addMember);


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
