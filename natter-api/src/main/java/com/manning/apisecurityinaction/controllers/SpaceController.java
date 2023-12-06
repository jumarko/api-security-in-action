package com.manning.apisecurityinaction.controllers;

import org.dalesbred.Database;
import org.json.JSONArray;
import org.json.JSONObject;
import spark.Request;
import spark.Response;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.stream.Collectors;

public class SpaceController {

    private static final Set<String> DEFINED_ROLES = Set.of("owner", "moderator", "member", "observer");

    private final Database database;
    private final CapabilityController capabilityController;

    public SpaceController(Database database) {
        this(database, null);
    }

    public SpaceController(Database database, CapabilityController capabilityController) {
        this.database = database;
        this.capabilityController = capabilityController;
    }

    /**
     * Adds permissions for given username.
     * Permissions are: 'r' for "read", 'w' for "write", 'd' for "delete".
     */
    private void addPermissions(long spaceId, String username, String permissions) {
        // NOTE: the table name was changed in chapter 8.1 to `user_permissions`, instead of former `permissions`
        // There's still the `permissions` view but we don't want to use that.
        database.updateUnique("INSERT INTO user_permissions(space_id, user_id, perms) VALUES(?, ?, ?)",
                    spaceId, username, permissions);
    }

    public JSONObject createSpace(Request request, Response response) {
        var json = new JSONObject(request.body());
        var spaceName = json.getString("name");
        var owner = json.getString("owner");

        var subject = request.attribute("subject");
        if (!owner.equals(subject)) {
            throw new IllegalArgumentException("owner must match authenticated user");
        }

        if (spaceName.length() > 255) {
            throw new IllegalArgumentException("space name too long");
        }

        if (!owner.matches(UserController.USERNAME_PATTERN.pattern())) {
            // note that echoing back the username might not be the best idea - see later in the book
            throw new IllegalArgumentException("invalid username");
        }

        // my custom addition for better error message in the browser
        var space = database.findOptional(String.class, "SELECT name from spaces WHERE name = ?", spaceName);
        if (space.isPresent()) {
            throw new IllegalArgumentException("Space already exists! You must provide a unique space name");
        }

        return database.withTransaction(tx -> {
            var spaceId = database.findUniqueLong("SELECT NEXT VALUE FOR space_id_seq;");

            // WARNING: SQL injection vulnerability - will be fixed later
            database.updateUnique("INSERT INTO spaces(space_id, name, owner) VALUES (?, ?, ?)",
                    spaceId, spaceName, owner);

            // give full permissions to the space owner
            // Chapter 8.1.2 - full permissions replaced with the owner role
            // addPermissions(spaceId, owner, "rwd");

            // Chapter 9.2.2 (p. 305/6) - Capability URIs
            // - no need to insert into user_roles anymore because we will be using capabilities for access control
//            database.updateUnique("INSERT INTO user_roles(space_id, user_id, role_id) " +
//                    "VALUES(?,?,?)", spaceId, owner, "owner");
            var spaceUri = "/spaces/" + spaceId;
            var expiry = Duration.ofDays(1000000); // very long duration as the URI is the only way to access the space from now on
            var uri = capabilityController.createURI(request, spaceUri, "rwd", expiry);

            response.status(201);
            response.header("Location", uri.toASCIIString());
            return new JSONObject().put("name", spaceName).put("uri", uri);
        });

    }

    public JSONObject addMember(Request request, Response response) {
        var requestJson = new JSONObject(request.body());
        var spaceId = Long.parseLong(request.params(":spaceId"));
        var userToAdd = requestJson.getString("username");

        if (database.findOptional(String.class,
                "SELECT user_id FROM users WHERE user_id=?", userToAdd)
                .isEmpty()) {
            throw new IllegalArgumentException("User does not exist");
        }

        // Chapter 8.1.2 - permissions replaced with roles
        // var perms = requestJson.getString("permissions");
//        if (StringUtils.isBlank(perms) || !perms.matches("r?w?d?")) {
//            throw new IllegalArgumentException("invalid perissions");
//        }
        var role = requestJson.optString("role", "member"); // default role is "member"
        if (!DEFINED_ROLES.contains(role)) {
            throw new IllegalArgumentException("invalid role");
        }
        database.updateUnique("INSERT INTO user_roles(space_id, user_id, role_id) " +
                "VALUES(?,?,?)", spaceId, userToAdd, role);

        // WARNING: possible privilege escalation attack!
        // It is mitigated by requiring full permissions for calling addMember endpoint
        // Chapter 8.1.2 - permissions replaced with roles
//        addPermissions(spaceId, userToAdd, perms);

        response.status(200);
        return new JSONObject()
                .put("username", userToAdd)
                // Chapter 8.1.2 - permissions replaced with roles
                // .put("permissions", perms);
                .put("role", role);
    }

    // Additional REST API endpoints not covered in the book:
    // - available here: https://github.com/NeilMadden/apisecurityinaction/tree/chapter03/natter-api/src/main/java/com/manning/apisecurityinaction/controller
    public JSONObject postMessage(Request request, Response response) {
        var spaceId = Long.parseLong(request.params(":spaceId"));
        var json = new JSONObject(request.body());
        var user = json.getString("author");
        if (!user.matches("[a-zA-Z][a-zA-Z0-9]{0,29}")) {
            throw new IllegalArgumentException("invalid username");
        }
        var message = json.getString("message");
        if (message.length() > 1024) {
            throw new IllegalArgumentException("message is too long");
        }

        return database.withTransaction(tx -> {
            var msgId = database.findUniqueLong(
                    "SELECT NEXT VALUE FOR msg_id_seq;");
            database.updateUnique(
                    "INSERT INTO messages(space_id, msg_id, msg_time," +
                            "author, msg_text) " +
                            "VALUES(?, ?, current_timestamp, ?, ?)",
                    spaceId, msgId, user, message);

            response.status(201);
            var uri = "/spaces/" + spaceId + "/messages/" + msgId;
            response.header("Location", uri);
            return new JSONObject().put("uri", uri);
        });
    }

    public Message readMessage(Request request, Response response) {
        var spaceId = Long.parseLong(request.params(":spaceId"));
        var msgId = Long.parseLong(request.params(":msgId"));

        var message = database.findUnique(Message.class,
                "SELECT space_id, msg_id, author, msg_time, msg_text " +
                        "FROM messages WHERE msg_id = ? AND space_id = ?",
                msgId, spaceId);

        response.status(200);
        return message;
    }

    public JSONArray findMessages(Request request, Response response) {
        var since = Instant.now().minus(1, ChronoUnit.DAYS);
        if (request.queryParams("since") != null) {
            since = Instant.parse(request.queryParams("since"));
        }
        var spaceId = Long.parseLong(request.params(":spaceId"));

        var messages = database.findAll(Long.class,
                "SELECT msg_id FROM messages " +
                        "WHERE space_id = ? AND msg_time >= ?;",
                spaceId, since);

        response.status(200);
        return new JSONArray(messages.stream()
                .map(msgId -> "/spaces/" + spaceId + "/messages/" + msgId)
                .collect(Collectors.toList()));
    }

    public static class Message {
        private final long spaceId;
        private final long msgId;
        private final String author;
        private final Instant time;
        private final String message;

        public Message(long spaceId, long msgId, String author,
                       Instant time, String message) {
            this.spaceId = spaceId;
            this.msgId = msgId;
            this.author = author;
            this.time = time;
            this.message = message;
        }
        @Override
        public String toString() {
            JSONObject msg = new JSONObject();
            msg.put("uri",
                    "/spaces/" + spaceId + "/messages/" + msgId);
            msg.put("author", author);
            msg.put("time", time.toString());
            msg.put("message", message);
            return msg.toString();
        }
    }
}
