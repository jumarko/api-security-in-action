package com.manning.apisecurityinaction;

import com.google.common.util.concurrent.RateLimiter;
import com.manning.apisecurityinaction.controllers.AuditController;
import com.manning.apisecurityinaction.controllers.ModeratorController;
import com.manning.apisecurityinaction.controllers.TokenController;
import com.manning.apisecurityinaction.controllers.UserController;
import com.manning.apisecurityinaction.token.DatabaseTokenStore;
import com.manning.apisecurityinaction.token.EncryptedJwtTokenStore;
import com.manning.apisecurityinaction.token.EncryptedTokenStore;
import com.manning.apisecurityinaction.token.JsonTokenStore;
import com.manning.apisecurityinaction.token.OAuth2TokenStore;
import com.nimbusds.jose.JOSEException;
import org.dalesbred.result.EmptyResultException;
import org.json.JSONException;
import org.json.JSONObject;
import software.pando.crypto.nacl.SecretBox;
import spark.Request;
import spark.Response;
import spark.Spark;

import com.manning.apisecurityinaction.controllers.SpaceController;
import org.dalesbred.Database;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.URI;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Set;

import javax.crypto.SecretKey;

/**
 * The main entry point that sets up the routes
 * Notice that in the book this is all in the Main class.
 */
public class WebApp {
    private final Database database;
    private final int port;

    public WebApp(Database database) {
        // listen on the default port 4567
        this(database, null);
    }

    public WebApp(Database database, Integer port) {
        this.database = database;
        this.port = port == null? spark.Service.SPARK_DEFAULT_PORT : port;
    }

    private void setupRateLimiting(int maxRequestsPerSecond) {
        Spark.port(port);
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

    private void setupCors() {
        Spark.before(new CorsFilter(Set.of("https://localhost:9999")));
    }

    public void init() throws UnrecoverableKeyException, CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, JOSEException {

        // serve static files like nater.js & natter.html saved in src/main/resources/public
        // this must be done before any route mapping has begun 
        Spark.staticFiles.location("/public");

        setupRateLimiting(5);
        setupCors();

        var spaceController = new SpaceController(database);

        var userController = new UserController(database);

        // chapter 5: replace CookieTokenStore with DatabaseTokenStore
        // var tokenController = new TokenController(new CookieTokenStore());

        // Chapter 6: replace DatabaseTokenStore with JsonTokenStore
        // var tokenStore = new HmacTokenStore(new DatabaseTokenStore(database), getHmacSecretKey());
        // var tokenStore = new HmacTokenStore(new JsonTokenStore(), getHmacSecretKey());

        // Chapter 6.2: replace JsonTokenStore with SignedJwtTokenStore
//        var macKey = getHmacSecretKey();
//        var signer = new MACSigner((SecretKey) macKey);
//        var verifier = new MACVerifier((SecretKey) macKey);
//        var tokenStore = new SignedJwtTokenStore(signer, verifier, JWSAlgorithm.HS256, "https://localhost:4567");

        // chapter 6.3 Authenticated encryption
        // NOTE: we use a different key - always use different keys for different purposes!!
        // Salty Coffee doesn't support keys generated by keytool directly so we convert them to a proper format

        // chapter 6.3.4 Replacing EncryptedTokenStore with EncryptedJwtTokenStore
        // var tokenStore = new EncryptedTokenStore(new JsonTokenStore(), getEncKey());
        // chapter 7.4 - replacing EncryptedJwtTokenStore with OAuth2TokenStore (p. 243)
        // var tokenStore = new EncryptedJwtTokenStore((SecretKey) getEncKey());
        var introspectionEndpoint = URI.create("http://as.example.com:8080/oauth2/introspect");
        // these are the client credentials you defined when configuring ForgeRok OAuth server
        // - see Applications -> Oauth 2.0 -> Clients: http://as.example.com:8080/XUI/?realm=/#realms/%2F/applications-oauth2
        var clientId = "test";
        var clientSecret = "changeit";
        var tokenStore = new OAuth2TokenStore(introspectionEndpoint, clientId, clientSecret);

        var tokenController = new TokenController(tokenStore);

        // authentication
        Spark.before(userController::authenticate);
        Spark.before(tokenController::validateToken);

        var auditController = new AuditController(database);
        Spark.before((auditController::auditRequestStart));
        Spark.afterAfter((auditController::auditRequestEnd));
        Spark.get("/logs", auditController::readAuditLog);

        Spark.before("/sessions", userController::requireAuthentication);
        // CH7: add scopes - login endpoint requires full_access to prevent privilege escalation
        Spark.before("/sessions", tokenController.requireScope("POST", "full_access"));
        Spark.post("/sessions", tokenController::login);
        // CH7 NOTE: logout endpoint doesn't require any scopes
        Spark.delete("/sessions", tokenController::logout);

        // require authentication for all /spaces requests          
        Spark.before("/spaces", userController::requireAuthentication);
        // CH7: add scopes
        Spark.before("/spaces", tokenController.requireScope("POST", "create_space"));
        Spark.post("/spaces", spaceController::createSpace);
        // only users with write permission can post messages
        Spark.before("/spaces/:spaceId/messages", userController.requirePermissions("POST", "w"));
        // CH7: add scopes
        Spark.before("/spaces/*/messages", tokenController.requireScope("POST", "post_message"));
        Spark.post("/spaces/:spaceId/messages", spaceController::postMessage);

        // only users with read permissions can read messages
        Spark.before("/spaces/:spaceId/messages", userController.requirePermissions("GET", "r"));
        // CH7: add scopes
        Spark.before("/spaces/*/messages", tokenController.requireScope("GET", "list_messages"));
        Spark.get("/spaces/:spaceId/messages/:msgId", spaceController::readMessage);
        // CH7: add scopes
        Spark.before("/spaces/*/messages/*", tokenController.requireScope("GET", "read_message"));
        Spark.before("/spaces/:spaceId/messages/*", userController.requirePermissions("GET", "r"));
        Spark.get("/spaces/:spaceId/messages", spaceController::findMessages);

        var moderatorController = new ModeratorController(database);
        Spark.before("/spaces/:spaceId/messages/:msgId", userController.requirePermissions("DELETE", "d"));

        Spark.delete("/spaces/:spaceId/messages/:msgId", moderatorController::deletePost);
        // CH7: add scopes
        Spark.before("/spaces/*/messages/*", tokenController.requireScope("DELETE", "delete_message"));
        Spark.post("/users", userController::registerUser);

        // notice we require 'rwd' permissions to avoid _privilege escalation_ attacks
        Spark.before("/spaces/:spaceId/members", userController.requirePermissions("POST", "rwd"));
        // CH7: add scopes
        Spark.before("/spaces/*/members", tokenController.requireScope("POST", "add_member"));
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

    private static Key getKey(String keyAlias) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        var keyPassword = System.getProperty("keystore.password", "changeit").toCharArray();
        var keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream("keystore.p12"), keyPassword);
        return keyStore.getKey(keyAlias, keyPassword);
    }
    private static Key getHmacSecretKey() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        return getKey("hmac-key");
    }

    private static Key getEncKey() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        return SecretBox.key(getKey("aes-key").getEncoded());
    }

    private static <T extends Exception> void badRequest(Exception e, Request request, Response response) {
        response.status(400);
        response.body(String.format("{\"error\": \"%s\"}", e.getMessage()));
    }
}
