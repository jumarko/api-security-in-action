package com.manning.apisecurityinaction.controllers;

import com.lambdaworks.crypto.SCryptUtil;
import org.dalesbred.Database;
import org.json.JSONObject;
import spark.Request;
import spark.Response;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * User registrationa and authentication.
 * `authenticate` performs the generic authentication stuff by checking Basic auth header
 * and comparing password with hash stored in the users table.
 */
public class UserController {

    private static final Pattern USERNAME_PATTERN = Pattern.compile("[a-zA-Z][a-zA-Z0-9]{1,29}");
    private final Database database;

    public UserController(Database database) {
        this.database = database;
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
            request.attribute("subject", username);
        }
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
}
