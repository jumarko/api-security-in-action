package com.manning.apisecurityinaction.controllers;

import com.lambdaworks.crypto.SCryptUtil;
import org.dalesbred.Database;
import org.dalesbred.query.QueryBuilder;
import org.json.JSONObject;
import spark.Filter;
import spark.Request;
import spark.Response;
import spark.Spark;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;

/**
 * User registrationa and authentication.
 * `authenticate` performs the generic authentication stuff by checking Basic auth header
 * and comparing password with hash stored in the users table.
 */
public class UserController {

    // In the book they use stricter validation but I use Hydra sample server
    // that uses `foo@bar.com` username
    // see https://www.ory.sh/docs/hydra/5min-tutorial
    public static final Pattern USERNAME_PATTERN = Pattern.compile("[a-zA-Z][a-zA-Z0-9@.]{1,29}");
    private final Database database;

    public UserController(Database database) {
        this.database = database;
    }


    public JSONObject registerUser(Request request, Response response) {
        var json = new JSONObject(request.body());
        var username = json.getString("username");
        var password = json.getString("password");

        if (!username.matches(USERNAME_PATTERN.pattern())) {
            throw new IllegalArgumentException("invalid username");
        }
        if (password.length() < 8) {
            throw new IllegalArgumentException("Password must be at least 8 characters long!");
        }

        // see https://blog.filippo.io/the-scrypt-parameters/ for recommended parameters
        // this will take ~32 MB of memory
        var hash = SCryptUtil.scrypt(password, 32768, 8, 1);
        database.updateUnique("INSERT INTO users(user_id, pw_hash) VALUES(?, ?)", username, hash);

        response.status(201);
        response.header("Location", "/users/" + username);
        return new JSONObject().put("username", username);
    }

    public void authenticate(Request request, Response response) {
        var authHeader = request.headers("Authorization");
        if (authHeader == null || !authHeader.startsWith("Basic")) {
            return;
        }

        var offset = "Basic ".length(); // notice there's a space after 'Basic'
        var credentials = new String(Base64.getDecoder().decode(
                authHeader.substring(offset)),
                StandardCharsets.UTF_8);
        var components = credentials.split(":", 2);
        if (components.length != 2) {
            throw new IllegalArgumentException("invalid auth header");
        }
        var username = components[0];
        var password = components[1];
        if (!username.matches(UserController.USERNAME_PATTERN.pattern())) {
            throw new IllegalArgumentException("invalid username");
        }

        var hash = database.findOptional(String.class,
                "SELECT pw_hash FROM users WHERE user_id=?", username);
        if (hash.isPresent() && SCryptUtil.check(password, hash.get())) {
            // Notice how all information about the user and their groups is collected in the Authentication step
            // and the access control decisions are made in the separate Authorization step (see requirePermissions)
            request.attribute("subject", username);

            var groups = database.findAll(String.class,
                    "SELECT DISTINCT group_id FROM group_members WHERE user_id =?",
                    username);
            request.attribute("groups", groups);
        }
    }

    public void requireAuthentication(Request request, Response response) {
        if (request.attribute("subject") == null) {
            // Chapter 4: Skip 'WWW-Authenticate' header to avoid ugly browser popups
            //   Note: technically, this is a violation of the RFC: https://datatracker.ietf.org/doc/html/rfc7235#section-3.1
            //   However, this patter is widespread
            // response.header("WWW-Authenticate", "Basic realm=\"/\", charset=\"UTF-8\"");
            // Chapter 5: re-introduce WWW-Authenticate for Bearer tokens - see also TokenController
            response.header("WWW-Authenticate", "Bearer");
            Spark.halt(401);
        }
    }

    /**
     * A factory method that creates a new Spark filter which can then check
     * whether particular method is allowed with given permissions.
     * If the method doesn't match, we skip the authorization.
     * @param method HTTP method
     * @param permission permission required for the API call to succeed
     * @return the filter that can be applied to specific route and checks permissions
     */
    public void lookupPermissions(Request request, Response response) {
        requireAuthentication(request, response);
        var spaceId = Long.parseLong(request.params(":spaceId"));
        var username = request.attribute("subject");
        // Chapter 8.2.3 (p. 279/280) - "permissions filter" - get user's permissions once and store them in a request attribute
        // - this enables us to reuse possibly expensive query multiple times over the same request
        var perms = database.findOptional(String.class,
                "SELECT rp.perms FROM role_permissions rp JOIN user_roles ur ON rp.role_id = ur.role_id" +
                " WHERE ur.space_id = ? AND ur.user_id = ?",
                spaceId, username).orElse("");
        request.attribute("perms", perms);
    }

    public Filter requirePermission(String method, String permission) {
        return (request, response) -> {
            if (!method.equalsIgnoreCase(request.requestMethod())) {
                return;
            }


            /* Older code using groups to determine permissions */
//            List<String> groups = request.attribute("groups");
//            var queryBuilder = new QueryBuilder("SELECT perms from permissions WHERE space_id = ? AND (user_or_group_id = ?",
//                    spaceId, username);
//            if (groups != null) { // TODO: this is needed because TokenController doesn't sets "groups" request attribute yet
//                for (var group : groups) {
//                    queryBuilder.append(" OR user_or_group_id = ?", group);
//                }
//            }
//            queryBuilder.append(")");
            // var perms = database.findAll(String.class, queryBuilder.build());
            //  if (perms.stream().noneMatch(p -> p.contains(permission))) {
            //                Spark.halt(403);
            //            }


            var perms = request.<String>attribute("perms");
            if (!perms.contains(permission)) {
                Spark.halt(403);
            }
        };
    }
}
