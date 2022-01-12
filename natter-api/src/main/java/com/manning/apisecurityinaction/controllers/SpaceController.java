package com.manning.apisecurityinaction.controllers;

import org.dalesbred.Database;
import org.json.JSONObject;
import spark.Request;
import spark.Response;

import java.sql.SQLException;

public class SpaceController {

    private final Database database;

    public SpaceController(Database database) {
        this.database = database;
    }

    public JSONObject createSpace(Request request, Response response) throws SQLException {
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
            // perms are: 'r' for "read", 'w' for "write", 'd' for "delete"
            database.updateUnique("INSERT INTO permissions(space_id, user_id, perms) VALUES(?, ?, ?)",
                    spaceId, owner, "rwd");

            response.status(201);
            var spaceUri = "/spaces/" + spaceId;
            response.header("Location", spaceUri);
            return new JSONObject().put("name", spaceName).put("uri", spaceUri);
        });

    }
}
