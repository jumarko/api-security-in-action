package com.manning.apisecurityinaction.controllers;

import org.dalesbred.Database;
import org.json.JSONArray;
import org.json.JSONObject;
import spark.Request;
import spark.Response;
import spark.utils.StringUtils;

import java.sql.SQLException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;

public class SpaceController {

    private final Database database;

    public SpaceController(Database database) {
        this.database = database;
    }

    /**
     * Adds permissions for given username.
     * Permissions are: 'r' for "read", 'w' for "write", 'd' for "delete".
     */
    private void addPermissions(long spaceId, String username, String permissions) {
        database.updateUnique("INSERT INTO permissions(space_id, user_id, perms) VALUES(?, ?, ?)",
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
        if (!owner.matches("[a-zA-Z][a-zA-Z0-9]{1,29}")) {
            // note that echoing back the username might not be the best idea - see later in the book
            throw new IllegalArgumentException("invalid username");
        }

        return database.withTransaction(tx -> {
            var spaceId = database.findUniqueLong("SELECT NEXT VALUE FOR space_id_seq;");

            // WARNING: SQL injection vulnerability - will be fixed later
            database.updateUnique("INSERT INTO spaces(space_id, name, owner) VALUES (?, ?, ?)",
                    spaceId, spaceName, owner);

            // give full permissions to the space owner
            addPermissions(spaceId, owner, "rwd");

            response.status(201);
            var spaceUri = "/spaces/" + spaceId;
            response.header("Location", spaceUri);
            return new JSONObject().put("name", spaceName).put("uri", spaceUri);
        });

    }

    public JSONObject addMember(Request request, Response response) {
        var requestJson = new JSONObject(request.body());
        var spaceId = Long.parseLong(request.params(":spaceId"));
        // TODO: maybe check that such a user exists?
        var userToAdd = requestJson.getString("username");
        var perms = requestJson.getString("permissions");

        if (database.findOptional(String.class,
                "SELECT user_id FROM users WHERE user_id=?", userToAdd)
                .isEmpty()) {
            throw new IllegalArgumentException("User does not exist");
        }

        if (StringUtils.isBlank(perms) || !perms.matches("r?w?d?")) {
            throw new IllegalArgumentException("invalid perissions");
        }

        // WARNING: possible privilege escalation attack!
        addPermissions(spaceId, userToAdd, perms);

        response.status(200);
        return new JSONObject()
                .put("username", userToAdd)
                .put("permissions", perms);
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
